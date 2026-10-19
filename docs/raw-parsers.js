// Local, bounded readers for Windows text exports. No network, storage, or execution.
const MAX_TEXT = 20 * 1024 * 1024;
const MAX_EVENTS = 50_000;
const MAX_MESSAGE = 20_000;
const EXTENSIONS = new Set(['log', 'txt', 'json', 'jsonl', 'ndjson', 'csv', 'xml']);
const KEY = value => String(value).replace(/[\s_@#-]/g, '').toLowerCase();
const OBJECT = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const own = (value, name) => Object.prototype.hasOwnProperty.call(value, name);
const GUID = /\b[\da-f]{8}-(?:[\da-f]{4}-){3}[\da-f]{12}\b/gi;
const CODE = /\b(?:0x[\da-f]{8}|AADSTS\d{5,8})\b/gi;
const STAMP = /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/i;
const ID_KEYS = new Set(['correlationid', 'activityid', 'relatedactivityid', 'requestid', 'sessionid', 'deviceid', 'appid', 'applicationid', 'tenantid', 'objectid']);
const RECORD_KEYS = new Set(['message', 'rendereddescription', 'description', 'msg', 'timecreated', 'timestamp', 'datetime', 'time', 'date', 'date(utc)', 'createddatetime', 'eventid', 'provider', 'providername', 'system', 'event', 'eventdata', 'status', 'errorcode', 'signinerrorcode', 'conditionalaccessstatus', 'appliedconditionalaccesspolicies', 'conditionalaccesspolicies', 'userprincipalname', 'activityid', 'correlationid']);

function lookup(record, ...names) {
  if (!OBJECT(record)) return undefined;
  const wanted = new Set(names.map(KEY));
  for (const [key, value] of Object.entries(record)) if (wanted.has(KEY(key)) && value !== null && value !== '') return value;
  return undefined;
}
function scalar(value) {
  if (OBJECT(value)) return lookup(value, '#text', 'text', 'value', 'DateTime');
  return value;
}
function short(value, maximum = MAX_MESSAGE) {
  const text = String(value ?? '');
  const suffix = ' [message truncated]';
  return text.length > maximum ? text.slice(0, maximum - suffix.length) + suffix : text;
}
function hash(value) {
  let a = 0x811c9dc5;
  let b = 0x9e3779b9;
  for (let i = 0; i < value.length; i++) {
    a = Math.imul(a ^ value.charCodeAt(i), 0x01000193);
    b = Math.imul(b ^ value.charCodeAt(i), 0x85ebca6b);
  }
  return (a >>> 0).toString(16).padStart(8, '0') + (b >>> 0).toString(16).padStart(8, '0');
}
function timestamp(value) {
  value = scalar(value);
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const text = String(value).trim();
  const dotnet = /^\/Date\((-?\d+)(?:[+-]\d{4})?\)\/$/.exec(text);
  if (dotnet) {
    const date = new Date(Number(dotnet[1]));
    return Number.isFinite(date.getTime()) ? date.toISOString() : null;
  }
  // Keep local clock timestamps without a suffix. Never infer the browser's timezone.
  const iso = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?(Z|[+-]\d{2}:?\d{2})?$/i.exec(text);
  const us = /^(\d{1,2})[-/](\d{1,2})[-/](\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s*(AM|PM)?$/i.exec(text);
  if (!iso && !us) return null;
  let year, month, day, hour, minute, second, fraction, zone;
  if (iso) [, year, month, day, hour, minute, second, fraction, zone] = iso;
  else {
    [, month, day, year, hour, minute, second, fraction] = us;
    if (us[8]) {
      if (+hour < 1 || +hour > 12) return null;
      hour = (+hour % 12) + (us[8].toUpperCase() === 'PM' ? 12 : 0);
    }
  }
  if (+year < 1000 || +month < 1 || +month > 12 || +day < 1 || +day > new Date(Date.UTC(+year, +month, 0)).getUTCDate() || +hour > 23 || +minute > 59 || +second > 59) return null;
  if (zone && zone !== 'Z' && zone !== 'z' && (+zone.slice(1, 3) > 23 || +zone.slice(-2) > 59)) return null;
  const pad = number => String(number).padStart(2, '0');
  const normalizedZone = zone ? (zone.toUpperCase() === 'Z' ? 'Z' : zone.replace(/^([+-]\d{2})(\d{2})$/, '$1:$2')) : '';
  return `${year}-${pad(month)}-${pad(day)}T${pad(hour)}:${minute}:${second}${fraction ? '.' + fraction : ''}${normalizedZone}`;
}
function category(source, message) {
  const text = (source + ' ' + message).toLowerCase();
  const filename = source.replace(/\\/g, '/').split('/').at(-1).toLowerCase();
  if (/\baadsts\d+\b/.test(text)) return 'Conditional Access';
  if (/appworkload|intunemanagementextension|appactionprocessor/.test(filename)) return 'Win32 apps';
  if (/conditional.?access|sign.?in|\bentra\b/.test(text)) return 'Conditional Access';
  if (/autopilot|enrollment status page|esp timeout|moderndeployment|provisioning.diagnostics|tpm attestation|enrollment fail|esp app|esp phase/.test(text)) return 'Autopilot & ESP';
  if (/windowsupdate|windows update|updateorchestrator|cbs\.log|servicing|update ring|0x800f081f|0x800f0831/.test(text)) return 'Windows patching';
  if (/win32|msiexec|msi |0x87d1041c|detection rule/.test(text)) return 'Win32 apps';
  return 'Enterprise';
}
function stage(message) {
  if (/\b(?:lpexitcode|exitcode|returncode|exit code|return code|result|succeeded|success|failed|failure|detected|detection)\b/i.test(message)) return 'result';
  if (/\b(?:install(?:ing|ation)?|execut(?:e|ing|ion)|command line|download(?:ing)?)\b/i.test(message)) return 'execution';
  if (/\b(?:assignment|assigned|targeting|targeted|excluded)\b/i.test(message)) return 'assignment';
  if (/\b(?:policy|profile|ring|deadline)\b/i.test(message)) return 'policy';
  return 'unknown';
}
function context(message) {
  const system = /\bSYSTEM\s+context\b|\b(?:context|running as|run as|executing as)\s*[=:]?\s*(?:NT AUTHORITY\\)?SYSTEM\b/i.test(message);
  const user = /\bUSER\s+context\b|\b(?:context|running as|run as|executing as)\s*[=:]?\s*USER\b/i.test(message);
  return system && user ? 'mixed' : system ? 'SYSTEM' : user ? 'User' : 'unknown';
}
function identifiers(record, message) {
  const found = new Set(message.match(GUID) || []);
  for (const match of message.matchAll(/\b(?:correlation|activity|relatedactivity|request|session|device|app(?:lication)?|tenant|object)[ _-]?id["']?\s*[=:]\s*["'{]?([\w.-]{3,})/gi)) found.add(match[1]);
  const stack = record ? [record] : [];
  while (stack.length) {
    const value = stack.pop();
    for (const [key, item] of Object.entries(value)) {
      if (ID_KEYS.has(KEY(key)) && (typeof item === 'string' || typeof item === 'number')) found.add(String(item));
      if (item && typeof item === 'object') stack.push(item);
    }
  }
  return [...found].slice(0, 100);
}
function codes(message) {
  const found = new Set([...message.matchAll(CODE)].map(match => match[0].toLowerCase().startsWith('aadsts') ? match[0].toUpperCase() : match[0].toLowerCase()));
  for (const match of message.matchAll(/\b(?:lpExitCode|exit\s*(?:code)?|return(?:ed)?\s*(?:code)?|installer\s*(?:error|code)|msi\s*(?:error|code))\s*(?:is\b|was\b|equals\b|[=:])?\s*(1603|1618|3010|1641)\b/gi)) found.add(match[1]);
  for (const match of message.matchAll(/\b(?:HRESULT|(?:error|result|return|exit)\s*code|lpExitCode)\s*(?:is\b|was\b|equals\b|[=:])?\s*(-?\d{6,10})\b/gi)) {
    const value = Number(match[1]);
    if ((value >= -2147483648 && value < 0) || (value > 65535 && value <= 4294967295)) found.add('0x' + (value >>> 0).toString(16).padStart(8, '0'));
  }
  return [...found];
}
function recordIsDiagnostic(record) {
  return OBJECT(record) && Object.keys(record).some(key => RECORD_KEYS.has(KEY(key)));
}
function flattenEvent(record) {
  const event = lookup(record, 'Event');
  if (OBJECT(event)) record = event;
  const system = lookup(record, 'System');
  if (!OBJECT(system)) return record;
  const provider = lookup(system, 'Provider');
  const time = lookup(system, 'TimeCreated');
  const correlation = lookup(system, 'Correlation');
  return {
    ...record,
    TimeCreated: OBJECT(time) ? lookup(time, 'SystemTime') : time,
    ProviderName: OBJECT(provider) ? lookup(provider, 'Name') : provider,
    EventId: scalar(lookup(system, 'EventId')),
    Level: scalar(lookup(system, 'Level')),
    ...(OBJECT(correlation) ? correlation : {})
  };
}
function recordParts(input) {
  const record = flattenEvent(input);
  let status = lookup(record, 'status');
  const entra = OBJECT(status) || lookup(record, 'conditionalAccessStatus', 'appliedConditionalAccessPolicies', 'conditionalAccessPolicies', 'userPrincipalName', 'sign-in error code') !== undefined;
  const timeFields = new Set(['TimeCreated', 'timestamp', 'DateTime', 'createdDateTime', 'Date (UTC)', 'Date', 'time'].map(KEY));
  const [timeKey, time] = Object.entries(record).find(([key, value]) => timeFields.has(KEY(key)) && value !== null && value !== '') || [];
  let parsedTime = timestamp(time);
  // Entra CSV labels this column UTC even when each cell omits a zone suffix.
  // Apply that explicit header only to the field actually selected above.
  if (parsedTime && KEY(timeKey) === 'date(utc)' && !/(?:Z|[+-]\d{2}:\d{2})$/i.test(parsedTime)) parsedTime += 'Z';
  const eventId = scalar(lookup(record, 'Id', 'EventId', 'Event ID'));
  const provider = scalar(lookup(record, 'ProviderName', 'Provider', 'Source'));
  const level = scalar(lookup(record, 'LevelDisplayName', 'Level', 'Severity', 'EntryType'));
  let message = lookup(record, 'Message', 'RenderedDescription', 'description', 'msg');
  if (message !== undefined && typeof message === 'object') message = JSON.stringify(message);
  if (entra) {
    let error = OBJECT(status) ? lookup(status, 'errorCode') : lookup(record, 'sign-in error code', 'errorCode');
    error = /^\d{5,8}$/.test(String(error)) && Number(error) !== 0 ? String(error) : '';
    message = (error ? `Entra sign-in AADSTS${error}: ` : 'Entra sign-in export: ') + JSON.stringify(record);
  } else {
    const metadata = Object.fromEntries(Object.entries(record).filter(([key]) => !['message', 'rendereddescription', 'description', 'msg', 'timecreated', 'timestamp', 'datetime', 'time'].includes(KEY(key))));
    const details = Object.keys(metadata).length ? JSON.stringify(metadata) : '';
    message = (message === undefined ? '' : String(message)) + (details ? '\n' + details : '');
  }
  return {message, timestamp: parsedTime, event_id: eventId === undefined ? undefined : String(eventId), provider: provider === undefined ? undefined : String(provider), level: level === undefined ? undefined : String(level), category: entra ? 'Conditional Access' : undefined, record};
}
function validateStructure(value) {
  const pending = [[value, 0]];
  let nodes = 0;
  while (pending.length) {
    const [item, depth] = pending.pop();
    if (++nodes > 1_000_000) throw new Error('Structured export is too complex. Split it into smaller files.');
    if (depth > 64) throw new Error('Structured export is nested too deeply. Export plain event or sign-in records.');
    if (item && typeof item === 'object') for (const child of Object.values(item)) pending.push([child, depth + 1]);
  }
}
function jsonRecords(value) {
  if (Array.isArray(value)) {
    if (!value.every(recordIsDiagnostic)) throw new Error('JSON must contain event or Entra sign-in objects with named diagnostic fields.');
    return value;
  }
  if (OBJECT(value)) {
    for (const name of ['value', 'events', 'records', 'signIns']) {
      const items = lookup(value, name);
      if (Array.isArray(items)) return jsonRecords(items);
    }
    if (recordIsDiagnostic(value)) return [value];
  }
  throw new Error('JSON does not contain supported event or Entra sign-in records. Export an event object or an array of records.');
}

function parseCSV(text, emit) {
  let row = [], field = '', quoted = false, closed = false, line = 1, rowLine = 1, headers = null;
  const finishRow = () => {
    row.push(field);
    field = '';
    closed = false;
    if (row.some(cell => cell.trim())) {
      if (!headers) {
        headers = row.map(cell => cell.trim());
        if (headers.some(cell => !cell) || new Set(headers.map(KEY)).size !== headers.length) throw new Error('CSV headers must be named and unique.');
        if (!headers.some(name => RECORD_KEYS.has(KEY(name)))) throw new Error('CSV requires named Windows event or Entra sign-in columns, such as Message, TimeCreated, or Sign-in error code.');
      } else {
        if (row.length !== headers.length) throw new Error(`CSV row at line ${rowLine} has ${row.length} values; ${headers.length} columns are required.`);
        emit(recordParts(Object.fromEntries(headers.map((name, i) => [name, row[i]]))), rowLine);
      }
    }
    row = [];
  };
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (char === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else { quoted = false; closed = true; }
      } else {
        field += char;
        if (char === '\n') line++;
      }
      continue;
    }
    if (char === '"') {
      if (field || closed) throw new Error(`Malformed CSV quoting near line ${line}.`);
      quoted = true;
    } else if (char === ',') {
      row.push(field); field = ''; closed = false;
    } else if (char === '\r' || char === '\n') {
      if (char === '\r' && text[i + 1] === '\n') i++;
      finishRow(); line++; rowLine = line;
    } else {
      if (closed && !/\s/.test(char)) throw new Error(`Unexpected CSV text after a closing quote near line ${line}.`);
      if (!closed) field += char;
    }
  }
  if (quoted) throw new Error(`CSV has an unterminated quoted field near line ${rowLine}.`);
  if (row.length || field || closed) finishRow();
}

function xmlEntities(value) {
  let output = '', offset = 0;
  const entity = /&([^;\s<&]*);/g;
  for (const match of value.matchAll(entity)) {
    const before = value.slice(offset, match.index);
    if (before.includes('&')) throw new Error('Malformed XML entity.');
    output += before;
    const name = match[1];
    const named = {amp: '&', lt: '<', gt: '>', quot: '"', apos: "'"};
    if (own(named, name)) output += named[name];
    else if (/^#(?:\d+|x[\da-f]+)$/i.test(name)) {
      const point = name[1].toLowerCase() === 'x' ? parseInt(name.slice(2), 16) : Number(name.slice(1));
      if (!(point === 9 || point === 10 || point === 13 || (point >= 32 && point <= 0xd7ff) || (point >= 0xe000 && point <= 0xfffd) || (point >= 0x10000 && point <= 0x10ffff))) throw new Error('XML contains an invalid character reference.');
      output += String.fromCodePoint(point);
    } else throw new Error('XML contains an unsupported entity. Export plain Windows Event XML without custom entities.');
    offset = match.index + match[0].length;
  }
  const rest = value.slice(offset);
  if (rest.includes('&')) throw new Error('Malformed XML entity.');
  return output + rest;
}
function xmlRecord(node) {
  const record = {}, data = [];
  const pending = [node];
  while (pending.length) {
    const child = pending.pop();
    for (let i = child.children.length - 1; i >= 0; i--) pending.push(child.children[i]);
    const content = child.text.trim();
    const attr = (...names) => lookup(child.attrs, ...names);
    if (child.local === 'TimeCreated') record.TimeCreated = attr('SystemTime');
    else if (child.local === 'Provider') record.ProviderName = attr('Name');
    else if (child.local === 'EventID') record.EventId = content;
    else if (child.local === 'Level') record.Level = content;
    else if (['Message', 'Channel', 'Computer'].includes(child.local)) record[child.local] = content;
    else if (child.local === 'Correlation') Object.assign(record, child.attrs);
    else if (child.local === 'Data') data.push({name: attr('Name') || `field${data.length + 1}`, value: content});
    else if (!child.children.length && content && !['Version', 'Task', 'Opcode', 'Keywords', 'EventRecordID'].includes(child.local)) data.push({name: child.local, value: content});
  }
  if (data.length) record.EventData = data;
  if (!recordIsDiagnostic(record)) throw new Error('XML Event record contains no diagnostic fields. Export complete Windows Event records.');
  return recordParts(record);
}
function parseXML(text, emit) {
  if (/<!\s*(?:DOCTYPE|ENTITY)\b/i.test(text)) throw new Error('XML DTD and entity declarations are unsupported. Export plain Windows Event XML.');
  const stack = [];
  let activeEvent = null, eventNodes = 0, roots = 0, count = 0, position = 0, line = 1;
  const fail = detail => { throw new Error(`Malformed Windows Event XML near line ${line}: ${detail}`); };
  const advance = end => { for (let i = position; i < end; i++) if (text[i] === '\n') line++; position = end; };
  const addText = (value, cdata = false) => {
    if (!stack.length && value.trim()) fail('text outside the root element.');
    if (stack.length && activeEvent) stack.at(-1).text = short(stack.at(-1).text + (cdata ? value : xmlEntities(value)));
    else if (!cdata) xmlEntities(value);
  };
  while (position < text.length) {
    if (text[position] !== '<') {
      const next = text.indexOf('<', position);
      const end = next === -1 ? text.length : next;
      const part = text.slice(position, end);
      if (part.includes(']]>')) fail('unexpected CDATA closing marker.');
      addText(part); advance(end); continue;
    }
    if (text.startsWith('<!--', position)) {
      const end = text.indexOf('-->', position + 4);
      if (end === -1 || text.slice(position + 4, end).includes('--')) fail('invalid comment.');
      advance(end + 3); continue;
    }
    if (text.startsWith('<![CDATA[', position)) {
      const end = text.indexOf(']]>', position + 9);
      if (end === -1 || !stack.length) fail('invalid CDATA section.');
      addText(text.slice(position + 9, end), true); advance(end + 3); continue;
    }
    if (text.startsWith('<?', position)) {
      const end = text.indexOf('?>', position + 2);
      if (end === -1) fail('unterminated declaration.');
      const body = text.slice(position + 2, end);
      if (!/^[A-Za-z_][\w.:-]*(?:\s|$)/.test(body)) fail('invalid processing instruction.');
      if (/^xml\b/i.test(body)) {
        if (roots || stack.length || position !== 0) fail('XML declaration must precede the root.');
        if (!/^xml\s+version\s*=\s*(["'])1\.[01]\1(?:\s+encoding\s*=\s*(["'])[A-Za-z][A-Za-z0-9._-]*\2)?(?:\s+standalone\s*=\s*(["'])(?:yes|no)\3)?\s*$/.test(body)) fail('invalid XML declaration.');
      }
      advance(end + 2); continue;
    }
    if (text.startsWith('<!', position)) fail('unsupported markup declaration.');
    // A quoted attribute may contain >. Walk to the actual end of this tag.
    let end = position + 1, quote = '';
    for (; end < text.length; end++) {
      const char = text[end];
      if (quote) { if (char === quote) quote = ''; }
      else if (char === '"' || char === "'") quote = char;
      else if (char === '>') break;
      else if (char === '<') fail('unexpected opening bracket in tag.');
    }
    if (end === text.length || quote) fail('unterminated tag.');
    const body = text.slice(position + 1, end);
    if (body.startsWith('/')) {
      const match = /^\/([A-Za-z_][\w.-]*(?::[A-Za-z_][\w.-]*)?)\s*$/.exec(body);
      if (!match || !stack.length || stack.at(-1).name !== match[1]) fail('mismatched closing tag.');
      const node = stack.pop();
      if (node === activeEvent) { emit(xmlRecord(node), node.line); activeEvent = null; count++; }
      else if (stack.length && activeEvent) stack.at(-1).text = short(stack.at(-1).text + node.text);
      advance(end + 1); continue;
    }
    const match = /^([A-Za-z_][\w.-]*(?::[A-Za-z_][\w.-]*)?)([\s\S]*)$/.exec(body);
    if (!match) fail('invalid element name.');
    const name = match[1], selfClosing = /\/$/.test(match[2]);
    let remainder = selfClosing ? match[2].replace(/\/$/, '') : match[2];
    const attrs = Object.create(null);
    while (remainder.trim()) {
      const attr = /^\s+([A-Za-z_][\w.-]*(?::[A-Za-z_][\w.-]*)?)\s*=\s*(?:"([^"<]*)"|'([^'<]*)')/.exec(remainder);
      if (!attr || own(attrs, attr[1])) fail('invalid or duplicate attribute.');
      attrs[attr[1]] = xmlEntities(attr[2] ?? attr[3]);
      remainder = remainder.slice(attr[0].length);
    }
    const ns = Object.assign(Object.create(null), stack.at(-1)?.ns || {xml: 'http://www.w3.org/XML/1998/namespace'});
    for (const [key, value] of Object.entries(attrs)) {
      if (key === 'xmlns') {
        if (value === 'http://www.w3.org/2000/xmlns/' || value === 'http://www.w3.org/XML/1998/namespace') fail('invalid default namespace.');
        ns[''] = value;
      } else if (key.startsWith('xmlns:')) {
        const prefix = key.slice(6);
        if (!value || prefix === 'xmlns' || (prefix === 'xml' && value !== 'http://www.w3.org/XML/1998/namespace') || (prefix !== 'xml' && value === 'http://www.w3.org/XML/1998/namespace') || value === 'http://www.w3.org/2000/xmlns/') fail('invalid namespace declaration.');
        ns[prefix] = value;
      }
    }
    if (name.includes(':') && (!ns[name.split(':')[0]] || name.startsWith('xmlns:'))) fail('unbound element namespace prefix.');
    const expandedAttrs = new Set();
    for (const key of Object.keys(attrs)) {
      if (key === 'xmlns' || key.startsWith('xmlns:')) continue;
      const [prefix, local] = key.includes(':') ? key.split(':') : ['', key];
      if (prefix && !ns[prefix]) fail('unbound attribute namespace prefix.');
      const expanded = `${prefix ? ns[prefix] : ''} ${local}`;
      if (expandedAttrs.has(expanded)) fail('duplicate expanded attribute name.');
      expandedAttrs.add(expanded);
    }
    if (!stack.length && ++roots > 1) fail('multiple root elements.');
    const node = {name, local: name.split(':').at(-1), attrs, ns, children: [], text: '', line};
    if (node.local === 'Event') {
      if (activeEvent) fail('nested Event elements are unsupported.');
      activeEvent = node;
      eventNodes = 0;
    } else if (activeEvent && stack.length) stack.at(-1).children.push(node);
    if (activeEvent && ++eventNodes > 20_000) fail('an Event record contains too many elements; split or simplify the export.');
    if (selfClosing) {
      if (node === activeEvent) { emit(xmlRecord(node), node.line); activeEvent = null; count++; }
    } else {
      stack.push(node);
      if (stack.length > 128) fail('element nesting is too deep.');
    }
    advance(end + 1);
  }
  if (stack.length || roots !== 1) fail('unclosed or missing root element.');
  if (!count) throw new Error('XML contains no Windows Event records. Export Event Viewer records as XML.');
}
function parseText(text, emit) {
  const expression = /<!\[LOG\[([\s\S]*?)\]LOG\]!><([^>]*)>/g;
  let previous = 0, line = 1;
  const plain = segment => {
    for (const message of segment.split(/\r?\n|\r/)) {
      if (message.trim()) emit({message, timestamp: timestamp(message.match(STAMP)?.[0])}, line);
      line++;
    }
    line--; // A segment ending mid-line does not advance to the next line.
  };
  for (const match of text.matchAll(expression)) {
    plain(text.slice(previous, match.index));
    const attrs = Object.create(null);
    for (const attr of match[2].matchAll(/(\w+)="([^"]*)"/g)) attrs[attr[1].toLowerCase()] = attr[2];
    const time = (attrs.time || '').replace(/[+-]\d{1,3}$/, '');
    emit({message: match[1], timestamp: timestamp(`${attrs.date || ''} ${time}`), provider: attrs.component || undefined, level: ({1: 'Information', 2: 'Warning', 3: 'Error'})[attrs.type]}, line);
    line += (match[0].match(/\n/g) || []).length;
    previous = match.index + match[0].length;
  }
  plain(text.slice(previous));
}

/** Parse one decoded text export. Raw values remain local; the caller redacts before presentation. */
export function parseRawLog(text, filename, options = {}) {
  if (typeof text !== 'string') throw new Error('Import requires decoded text. Choose a supported text log or event export.');
  if (typeof filename !== 'string' || !filename.trim() || filename.length > 1024) throw new Error('A valid log filename is required.');
  const extension = filename.replace(/\\/g, '/').split('/').at(-1).split('.').at(-1).toLowerCase();
  if (!EXTENSIONS.has(extension)) throw new Error('Unsupported file type. Import .log, .txt, .json, .jsonl, .ndjson, .csv, or Windows Event .xml. Extract CAB files first; native EVTX and ETL need text export.');
  if (text.length > MAX_TEXT) throw new Error('File exceeds the 20 MiB text import limit. Split the export into smaller files.');
  text = text.replace(/^\uFEFF/, '');
  if (!text.trim()) throw new Error('The selected file is empty. Choose a log containing diagnostic records.');
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text) || /^(?:MSCF|ElfFile|MZ)/.test(text)) throw new Error('This file contains binary data. Extract a CAB or export EVTX/ETL as supported text before importing.');
  const requested = options.maxEvents === undefined ? MAX_EVENTS : options.maxEvents;
  if (!Number.isInteger(requested) || requested < 1) throw new Error('The event limit must be a positive integer.');
  const limit = Math.min(requested, MAX_EVENTS), events = [], warnings = [];
  let total = 0, skipped = 0;
  const sourceHash = hash(filename);
  const emit = (parts, line) => {
    total++;
    if (events.length >= limit) return;
    const message = short(parts.message);
    const event = {
      uid: `raw-${sourceHash}-${total}`,
      source: filename,
      line,
      message,
      timestamp: parts.timestamp || null,
      category: parts.category || category(filename + ' ' + (parts.provider || ''), message),
      stage: stage(message),
      context: context(message),
      codes: codes(message),
      correlation_ids: identifiers(parts.record, message)
    };
    for (const key of ['event_id', 'provider', 'level']) if (parts[key] !== undefined) event[key] = short(parts[key], 512);
    events.push(event);
  };
  if (extension === 'json') {
    let value;
    try { value = JSON.parse(text); } catch { throw new Error('Malformed JSON export. Choose an event/sign-in JSON export or a Windows Diagnostics report.'); }
    validateStructure(value);
    jsonRecords(value).forEach((record, index) => emit(recordParts(record), index + 1));
  } else if (extension === 'jsonl' || extension === 'ndjson') {
    text.split(/\r?\n|\r/).forEach((line, index) => {
      if (!line.trim()) return;
      try {
        const record = JSON.parse(line);
        validateStructure(record);
        if (!recordIsDiagnostic(record)) throw new Error('record');
        emit(recordParts(record), index + 1);
      } catch {
        skipped++;
        if (warnings.length < 20) warnings.push(`Skipped malformed or unsupported JSON record at line ${index + 1}.`);
      }
    });
    if (skipped > 20) warnings.push(`${skipped - 20} additional invalid JSON lines were skipped.`);
  } else if (extension === 'csv') parseCSV(text, emit);
  else if (extension === 'xml') parseXML(text, emit);
  else parseText(text, emit);
  if (!events.length) throw new Error(skipped ? 'No usable event records were found. JSONL/NDJSON requires one diagnostic object per line.' : 'No diagnostic records were found in this export.');
  if (total > limit) warnings.push(`Showing the first ${limit.toLocaleString('en-US')} of ${total.toLocaleString('en-US')} records. Split the file to analyze the remaining records.`);
  return {events, warnings};
}
