/** Shared pure helpers, safe to import in both the UI and import worker. */
export const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
export const last = values => values[values.length - 1];
export function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
}
const numberFormatter = new Intl.NumberFormat('en-US');
export const formatNumber = value => numberFormatter.format(Number(value || 0));
export const uniqueMessages = values => [...new Set(values.filter(value => typeof value === 'string' && value.length))];
export const reportWarnings = reports => uniqueMessages(reports.flatMap(report => report.warnings || []));

// Profiles preserve previously exported identifiers, including the analyzer's
// historical handling of non-BMP characters. These digests are not cryptographic.
const profiles = {
  stable: {seed:2246822519, factor:3266489917},
  parser: {seed:0x9e3779b9, factor:0x85ebca6b},
  analysis: {seed:2246822519, factor:3266489917}
};
export function hashText(value, profile='stable') {
  if (!hasOwn(profiles, profile)) throw new RangeError('Unknown digest profile');
  const {seed, factor} = profiles[profile];
  let a=2166136261, b=seed;
  for (let index=0; index<value.length; index++) {
    const unit=value.charCodeAt(index);
    a=Math.imul(a ^ unit,16777619);b=Math.imul(b ^ unit,factor);
    if (profile==='analysis' && unit>=0xd800 && unit<=0xdbff && value.charCodeAt(index+1)>=0xdc00 && value.charCodeAt(index+1)<=0xdfff) index++;
  }
  return (a>>>0).toString(16).padStart(8,'0')+(b>>>0).toString(16).padStart(8,'0');
}
