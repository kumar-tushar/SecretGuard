(() => {
  'use strict';
  const origins = new Set(chrome.runtime.getManifest().content_scripts.flatMap(script => script.matches.map(value => new URL(value).origin)));
  let worker, port, timer, started = false;
  function stop() {
    clearTimeout(timer);
    worker?.terminate(); worker = null;
    port?.close(); port = null;
  }
  function finish(message) {
    try { port?.postMessage(message); } finally { stop(); }
  }
  window.addEventListener('pagehide', stop, { once: true });
  window.addEventListener('message', event => {
    if (started || event.source !== parent || !origins.has(event.origin) ||
        event.data?.type !== 'ckretguard-scan' || event.ports.length !== 1) return;
    started = true;
    port = event.ports[0];
    port.onmessage = () => stop();
    port.onmessageerror = () => stop();
    try {
      timer = setTimeout(() => finish({ ok: false, code: 'timeout' }), 5000);
      worker = new Worker('scan-worker.js');
      worker.onmessage = event => finish(event.data);
      worker.onerror = event => { event.preventDefault(); finish({ ok: false }); };
      worker.onmessageerror = () => finish({ ok: false });
      worker.postMessage({ text: event.data.text, policy: event.data.policy });
    } catch { finish({ ok: false }); }
  });
})();
