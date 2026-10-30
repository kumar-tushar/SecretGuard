'use strict';
importScripts('gitleaks-rules.js', 'core.js');
self.onmessage = ({ data }) => {
  try {
    const { text, policy } = data;
    self.postMessage({ ok: true, result: SecretShieldCore.redact(text, policy, text.length) });
  } catch { self.postMessage({ ok: false }); }
};
