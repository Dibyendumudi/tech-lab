/** Keep export URLs alive for delayed browser Save dialogs; no completion timer exists. */
const sessions = new WeakMap();
export function downloadBlob(blob, filename, doc=document) {
  let session=sessions.get(doc);
  if (!session) {
    session={urls:new Set()};sessions.set(doc,session);
    const view=doc.defaultView;
    view?.addEventListener('pagehide', event => {
      // A bfcache restore keeps this document alive, so preserve pending exports.
      if (event.persisted) return;
      for (const url of session.urls) URL.revokeObjectURL(url);
      session.urls.clear();
    });
  }
  const url=URL.createObjectURL(blob);session.urls.add(url);
  const anchor=doc.createElement('a');anchor.href=url;anchor.download=filename;
  try {doc.body.append(anchor);anchor.click();}
  catch (error) {session.urls.delete(url);URL.revokeObjectURL(url);throw error;}
  finally {anchor.remove();}
  // Browsers also release object URLs automatically when the document unloads.
  return url;
}
