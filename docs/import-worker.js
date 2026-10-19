import { importDiagnosticFiles } from './importer.js';

self.onmessage = async event => {
  try { self.postMessage({ result: await importDiagnosticFiles(event.data.files) }); }
  catch (error) { self.postMessage({ error: error.message || 'Local import could not complete.' }); }
};
