import { importDiagnosticFiles } from './importer.js?v=1.6.4';

self.onmessage = async event => {
  try { self.postMessage({ result: await importDiagnosticFiles(event.data.files, event.data.options) }); }
  catch (error) { self.postMessage({ error: error.message || 'Local import could not complete.' }); }
};
