import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('../src/scanner.js', import.meta.url), 'utf8');
function fixture() {
  const frames = [], timers = new Map(), channels = [];
  let next = 0;
  const context = vm.createContext({ URL, AbortController,
    SecretShieldCore: { ScanError: class extends Error {}, MASK: 'xxxxxxxxxx', normalizePolicy: value => value ?? {} },
    chrome: { runtime: { id: 'test-id', getURL: name => `chrome-extension://test-id/${name}` } },
    setTimeout: (callback, ms) => { const id = ++next; timers.set(id, { callback, ms }); return id; },
    clearTimeout: id => timers.delete(id),
    MessageChannel: class {
      constructor() {
        this.port1 = { postMessage() {}, close() { this.closed = true; } };
        this.port2 = { close() { this.closed = true; } };
        channels.push(this);
      }
    },
    document: {
      createElement: () => {
        const frame = { listeners: {}, style: { setProperty() {} }, setAttribute() {},
          addEventListener(type, listener) { this.listeners[type] = listener; },
          remove() { this.removed = true; },
          contentWindow: { postMessage(message, origin, ports) { frame.request = { message, origin, ports }; } } };
        return frame;
      },
      body: { append(frame) { frames.push(frame); } },
    },
  });
  vm.runInContext(source, context);
  const reply = data => channels.at(-1).port1.onmessage({ data });
  const complete = text => reply({ ok: true, result: { text, count: 0, findings: [] } });
  return { api: context.SecretShieldScanner, frames, timers, channels, reply, complete };
}

test('scanner sends only to the extension frame over a transferred private port and cleans up success', async () => {
  const state = fixture();
  const result = state.api.redact('ordinary prompt', { mode: 'redact' });
  const frame = state.frames[0];
  assert.equal(frame.hidden, true);
  assert.equal(frame.request, undefined);
  frame.listeners.load();
  assert.equal(frame.request.origin, 'chrome-extension://test-id');
  assert.equal(frame.request.message.text, 'ordinary prompt');
  assert.equal(frame.request.ports.length, 1);
  assert.equal(frame.request.ports[0], state.channels[0].port2);
  state.complete('ordinary prompt');
  assert.equal((await result).count, 0);
  assert.equal(frame.removed, true);
  assert.equal(state.channels[0].port1.closed, true);
  assert.equal(state.timers.size, 0);
});

test('the five-second deadline covers loading and removes the frame on timeout', async () => {
  const state = fixture(), result = state.api.redact('retain this');
  const rejected = assert.rejects(result, { code: 'timeout' });
  assert.equal(state.api.timeout, 5000);
  const [timer] = state.timers.values();
  assert.equal(timer.ms, 5000);
  timer.callback();
  await rejected;
  assert.equal(state.frames[0].removed, true);
  assert.equal(state.channels[0].port1.closed, true);
  state.frames[0].listeners.load();
  assert.equal(state.frames[0].request, undefined, 'expired loading must not start a scan');
});

test('aborting before or during a scan discards late responses and allows a fresh scan', async () => {
  for (const early of [true, false]) {
    const state = fixture(), controller = new AbortController();
    if (early) controller.abort();
    const result = state.api.redact('old draft', undefined, { signal: controller.signal });
    const rejected = assert.rejects(result, { code: 'cancelled' });
    if (!early) {
      state.frames[0].listeners.load();
      controller.abort();
      state.complete('old draft');
      assert.equal(state.frames[0].removed, true);
    } else assert.equal(state.frames.length, 0);
    await rejected;
    const fresh = state.api.redact('new draft');
    state.complete('new draft');
    assert.equal((await fresh).text, 'new draft');
    assert.equal(state.timers.size, 0);
  }
});

test('worker failures, protocol errors and malformed spans fail closed', async () => {
  const invalid = [null, { ok: false }, { ok: true, result: null },
    { ok: true, result: { text: 'different prompt', count: 0, findings: [] } },
    { ok: true, result: { text: '', count: 1, findings: [] } },
    ...[{ start: -1, end: 2, type: 'test' }, { start: 1, end: 1, type: 'test' },
      { start: 1.2, end: 2, type: 'test' }, { start: 1, end: 20, type: 'test' },
      { start: 1, end: 2, type: 1 }].map(item => ({ ok: true, result: { text: '', count: 1, findings: [item] } })),
    { ok: true, result: { text: '', count: 2, findings: [{ start: 1, end: 3, type: 'test' }, { start: 2, end: 4, type: 'test' }] } }];
  for (const reply of invalid) {
    const state = fixture(), result = state.api.redact('original');
    const rejected = assert.rejects(result);
    state.reply(reply);
    await rejected;
    assert.equal(state.frames[0].removed, true);
  }
  for (const type of ['error', 'messageerror']) {
    const state = fixture(), result = state.api.redact('original');
    const rejected = assert.rejects(result);
    if (type === 'error') state.frames[0].listeners.error();
    else state.channels[0].port1.onmessageerror();
    await rejected;
    assert.equal(state.frames[0].removed, true);
  }
});

test('verified redaction uses complete UTF-16 ranges and concurrent scans remain independent', async () => {
  const state = fixture(), input = '😀 client_id=demo';
  const first = state.api.redact(input), second = state.api.redact('ordinary');
  const start = input.indexOf('demo');
  state.channels[0].port1.onmessage({ data: { ok: true, result: { text: '😀 client_id=xxxxxxxxxx', count: 1,
    findings: [{ start, end: input.length, type: 'client-id' }] } } });
  state.complete('ordinary');
  assert.equal((await first).text, '😀 client_id=xxxxxxxxxx');
  assert.equal((await second).count, 0);
  assert.ok(state.frames.every(frame => frame.removed));
  assert.equal(state.timers.size, 0);
});

test('verified worker findings preserve canonical encoding tags and reject malformed metadata', async () => {
  const valid = [['decoded:hex', 'decode-depth:2'], ['decoded:percent', 'decoded:hex', 'decoded:base64', 'decode-depth:3']];
  const invalid = [null, 'decoded:hex', [], ['decode-depth:1'], ['decoded:hex'],
    ['decoded:hex', 'decode-depth:0'], ['decoded:hex', 'decode-depth:4'],
    ['decoded:unicode', 'decode-depth:1'], ['decoded:hex', 'decoded:hex', 'decode-depth:1'],
    ['decoded:base64', 'decoded:hex', 'decode-depth:2'], ['decoded:hex', 'decode-depth:1', 'decode-depth:2'],
    ['decoded:hex', 2], ['decoded:hex', 'secret-value'], ['decoded:hex', 'decode-depth:1', 'extra']];
  for (const tags of [...valid, ...invalid]) {
    const state = fixture(), result = state.api.redact('original');
    const rejected = invalid.includes(tags) ? assert.rejects(result, { code: 'invalid' }) : null;
    state.reply({ ok: true, result: { text: 'xxxxxxxxxx', count: 1, findings: [{ start: 0, end: 8, type: 'test', tags }] } });
    if (rejected) await rejected;
    else assert.deepEqual((await result).findings[0].tags, tags);
    assert.equal(state.frames[0].removed, true);
    assert.equal(state.channels[0].port1.closed, true);
    assert.equal(state.timers.size, 0);
  }
});
