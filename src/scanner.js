(() => {
  'use strict';
  const timeout = 5000;
  function failure(code) {
    const error = new SecretShieldCore.ScanError();
    error.code = code;
    return error;
  }
  function redact(text, policy, { signal, ruleIds } = {}) {
    return new Promise((resolve, reject) => {
      let frame, channel, timer, settled = false;
      function finish(error, result) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', cancel);
        try { channel?.port1.postMessage({ type: 'cancel' }); } catch {}
        channel?.port1.close(); channel?.port2.close();
        frame?.remove();
        if (error) reject(error); else resolve(result);
      }
      function cancel() { finish(failure('cancelled')); }
      try {
        if (signal?.aborted) { cancel(); return; }
        if (typeof text !== 'string') throw failure('invalid');
        const settings = SecretShieldCore.normalizePolicy(policy);
        const selected = SecretShieldCore.normalizeRuleIds(ruleIds), enabled = selected && new Set(selected);
        const metadata = new Map(SecretShieldRules.rules.map(rule => [rule.id, rule]));
        const url = chrome.runtime.getURL('scan-host.html');
        const origin = new URL(url).origin === 'null' ? `chrome-extension://${chrome.runtime.id}` : new URL(url).origin;
        frame = document.createElement('iframe');
        frame.hidden = true; frame.tabIndex = -1; frame.setAttribute('aria-hidden', 'true');
        frame.style.setProperty('display', 'none', 'important');
        frame.src = url;
        channel = new MessageChannel();
        signal?.addEventListener('abort', cancel, { once: true });
        timer = setTimeout(() => finish(failure('timeout')), timeout);
        channel.port1.onmessageerror = () => finish(failure('unavailable'));
        channel.port1.onmessage = ({ data }) => {
          try {
            if (!data?.ok) throw failure(data?.code === 'timeout' ? 'timeout' : 'unavailable');
            const result = data.result;
            if (!result || typeof result.text !== 'string' || !Array.isArray(result.findings) ||
                result.count !== result.findings.length) throw failure('invalid');
            let cursor = 0, expected = '';
            for (const item of result.findings) {
              if (!Number.isSafeInteger(item.start) || !Number.isSafeInteger(item.end) || item.start < cursor ||
                  item.end <= item.start || item.end > text.length || typeof item.type !== 'string') throw failure('invalid');
              if (enabled && !enabled.has(item.type) && !['custom-field', 'client-id'].includes(item.type)) throw failure('invalid');
              const rule = metadata.get(item.type), ruleTags = rule?.tags ?? [];
              if (item.description !== rule?.description || item.description !== undefined &&
                  (typeof item.description !== 'string' || item.description.length > 2048)) throw failure('invalid');
              if (item.tags !== undefined && (!Array.isArray(item.tags) || !item.tags.length || item.tags.length > 68 ||
                  item.tags.some(tag => typeof tag !== 'string' || !tag || tag.length > 256)) ||
                  ruleTags.some((tag, index) => item.tags?.[index] !== tag)) throw failure('invalid');
              const decodedTags = (item.tags ?? []).slice(ruleTags.length);
              if (decodedTags.length && !/^(?:decoded:percent,)?(?:decoded:hex,)?(?:decoded:base64,)?decode-depth:[1-3]$/.test(decodedTags.join(',')) ||
                  decodedTags.length === 1) throw failure('invalid');
              expected += text.slice(cursor, item.start) + SecretShieldCore.MASK;
              cursor = item.end;
            }
            if (result.text !== expected + text.slice(cursor)) throw failure('invalid');
            const locations = SecretShieldCore.findingLocations(text, result.findings);
            for (let i = 0; i < locations.length; i++) for (const key of ['startLine', 'startColumn', 'endLine', 'endColumn']) {
              if (result.findings[i][key] !== locations[i][key]) throw failure('invalid');
            }
            finish(null, result);
          } catch (error) { finish(error); }
        };
        frame.addEventListener('load', () => {
          if (settled) return;
          try {
            frame.contentWindow.postMessage({ type: 'ckretguard-scan', text, policy: settings,
              ...(selected ? { ruleIds: selected } : {}) }, origin, [channel.port2]);
          } catch { finish(failure('unavailable')); }
        }, { once: true });
        frame.addEventListener('error', () => finish(failure('unavailable')), { once: true });
        (document.body ?? document.documentElement).append(frame);
      } catch (error) { finish(error); }
    });
  }
  globalThis.SecretShieldScanner = Object.freeze({ redact, timeout });
})();
