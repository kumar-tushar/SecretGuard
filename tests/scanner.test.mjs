import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import '../src/index.mjs';
import { withLocations } from './fixtures/finding-locations.mjs';

const source = await readFile(new URL('../src/scanner.js', import.meta.url), 'utf8');
const core = await readFile(new URL('../src/core.js', import.meta.url), 'utf8');
function fixture(rules = []) {
  const frames = [], timers = new Map(), channels = [];
  let next = 0;
  const context = vm.createContext({ URL, AbortController, SecretShieldRules: { rules },
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
  vm.runInContext(core, context);
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

test('rule selection is copied, deduplicated and sent privately while concurrent and default scans stay independent', async () => {
  const state = fixture([{ id: 'first' }, { id: 'second' }]);
  const ids = ['second', 'first', 'second'];
  const first = state.api.redact('one', undefined, { ruleIds: ids });
  const second = state.api.redact('two', undefined, { ruleIds: ['second'] });
  const third = state.api.redact('three', undefined, { ruleIds: [] });
  ids.splice(0, ids.length, 'unknown');
  for (const frame of state.frames) frame.listeners.load();
  assert.deepEqual(Array.from(state.frames[0].request.message.ruleIds), ['first', 'second']);
  assert.deepEqual(Array.from(state.frames[1].request.message.ruleIds), ['second']);
  assert.equal(state.frames[2].request.message.ruleIds, undefined);
  for (let i = 0; i < 3; i++) state.channels[i].port1.onmessage({ data: { ok: true,
    result: { text: ['one', 'two', 'three'][i], count: 0, findings: [] } } });
  assert.deepEqual((await Promise.all([first, second, third])).map(result => result.count), [0, 0, 0]);
  const retry = state.api.redact('default');
  state.frames.at(-1).listeners.load();
  assert.equal(state.frames.at(-1).request.message.ruleIds, undefined);
  state.complete('default'); await retry;
  assert.ok(state.frames.every(frame => frame.removed));
  assert.equal(state.timers.size, 0);
});

test('invalid rule selections reject before loading a frame, retain safe errors and allow retry', async () => {
  for (const ruleIds of [null, 'first', ['FIRST'], ['first', 'unknown'], Array(1), Array(1001).fill('first')]) {
    const state = fixture([{ id: 'first' }]);
    await assert.rejects(state.api.redact('', undefined, { ruleIds }), error =>
      error.message === 'This text could not be scanned. Keep it local and shorten it before retrying.');
    assert.equal(state.frames.length, 0);
    assert.equal(state.timers.size, 0);
    const retry = state.api.redact('retained');
    state.complete('retained');
    assert.equal((await retry).text, 'retained');
  }
});

test('unselected or unknown worker rule IDs are rejected with cleanup and a fresh valid retry', async () => {
  for (const type of ['second', 'unknown']) {
    const state = fixture([{ id: 'first' }, { id: 'second' }]);
    const result = state.api.redact('original', undefined, { ruleIds: ['first'] });
    const rejected = assert.rejects(result, { code: 'invalid' });
    state.reply({ ok: true, result: { text: 'xxxxxxxxxx', count: 1,
      findings: withLocations('original', [{ start: 0, end: 8, type }]) } });
    await rejected;
    assert.equal(state.frames[0].removed, true);
    assert.equal(state.channels[0].port1.closed, true);
    assert.equal(state.timers.size, 0);
    const retry = state.api.redact('original', undefined, { ruleIds: ['first'] });
    state.reply({ ok: true, result: { text: 'xxxxxxxxxx', count: 1,
      findings: withLocations('original', [{ start: 0, end: 8, type: 'first' }]) } });
    assert.equal((await retry).count, 1);
  }
});

test('selected worker responses still accept custom-field and client-ID findings with validated locations', async () => {
  for (const type of ['custom-field', 'client-id']) {
    const state = fixture([{ id: 'first' }]);
    const result = state.api.redact('original', undefined, { ruleIds: ['first'] });
    state.reply({ ok: true, result: { text: 'xxxxxxxxxx', count: 1,
      findings: withLocations('original', [{ start: 0, end: 8, type }]) } });
    assert.equal((await result).findings[0].type, type);
  }
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
    findings: withLocations(input, [{ start, end: input.length, type: 'client-id' }]) } } });
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
    state.reply({ ok: true, result: { text: 'xxxxxxxxxx', count: 1, findings: withLocations('original', [{ start: 0, end: 8, type: 'test', tags }]) } });
    if (rejected) await rejected;
    else assert.deepEqual((await result).findings[0].tags, tags);
    assert.equal(state.frames[0].removed, true);
    assert.equal(state.channels[0].port1.closed, true);
    assert.equal(state.timers.size, 0);
  }
});

test('worker metadata must match the bundled rule description and exact configured tag prefix', async () => {
  const rules = [{ id: 'test', description: 'Configured service credential', tags: ['service', 'api', 'service'] }];
  const valid = [
    { description: rules[0].description, tags: rules[0].tags },
    { description: rules[0].description, tags: [...rules[0].tags, 'decoded:hex', 'decode-depth:2'] },
  ];
  const invalid = [
    {}, { description: 'Other description', tags: rules[0].tags },
    { description: null, tags: rules[0].tags }, { description: 1, tags: rules[0].tags },
    { description: 'x'.repeat(2049), tags: rules[0].tags },
    { description: rules[0].description }, { description: rules[0].description, tags: [] },
    { description: rules[0].description, tags: ['service', 'service', 'api'] },
    { description: rules[0].description, tags: [...rules[0].tags, 'invented'] },
    { description: rules[0].description, tags: [...rules[0].tags, 'decode-depth:2'] },
    { description: rules[0].description, tags: [...rules[0].tags, 'decoded:hex'] },
    { description: rules[0].description, tags: [...rules[0].tags, 'decoded:hex', 'decode-depth:4'] },
    { description: rules[0].description, tags: [...rules[0].tags, 'decoded:base64', 'decoded:hex', 'decode-depth:2'] },
  ];
  for (const metadata of [...valid, ...invalid]) {
    const state = fixture(rules), result = state.api.redact('original');
    const rejected = invalid.includes(metadata) ? assert.rejects(result, { code: 'invalid' }) : null;
    state.reply({ ok: true, result: { text: 'xxxxxxxxxx', count: 1, findings: withLocations('original', [{ start: 0, end: 8, type: 'test', ...metadata }]) } });
    if (rejected) await rejected;
    else assert.deepEqual(JSON.parse(JSON.stringify((await result).findings[0])), withLocations('original', [{ start: 0, end: 8, type: 'test', ...metadata }])[0]);
    assert.equal(state.frames[0].removed, true);
    assert.equal(state.channels[0].port1.closed, true);
    assert.equal(state.timers.size, 0);
    const retry = state.api.redact('safe retry');
    state.complete('safe retry');
    assert.equal((await retry).count, 0);
  }
});

test('worker metadata preserves empty descriptions, maximum bounds and configured encoding-like tags', async () => {
  for (const metadata of [
    { description: '', tags: ['decoded:hex', 'decode-depth:2', 'decoded:hex', 'decode-depth:1'] },
    { description: 'x'.repeat(2048), tags: [...Array(64).fill('t'.repeat(256)), 'decoded:percent', 'decoded:hex', 'decoded:base64', 'decode-depth:3'] },
  ]) {
    const ruleTags = metadata.description === '' ? metadata.tags.slice(0, 2) : metadata.tags.slice(0, 64);
    const state = fixture([{ id: 'test', description: metadata.description, tags: ruleTags }]);
    const result = state.api.redact('original');
    state.reply({ ok: true, result: { text: 'xxxxxxxxxx', count: 1, findings: withLocations('original', [{ start: 0, end: 8, type: 'test', ...metadata }]) } });
    assert.deepEqual((await result).findings[0].tags, metadata.tags);
  }
  const state = fixture(), result = state.api.redact('original');
  const rejected = assert.rejects(result, { code: 'invalid' });
  state.reply({ ok: true, result: { text: 'xxxxxxxxxx', count: 1, findings: [{ start: 0, end: 8, type: 'custom-field', description: 'Invented label' }] } });
  await rejected;
});

test('worker locations must exactly match the original prompt and fail closed on missing or altered coordinates', async () => {
  const input = '😀\nclient_id="é\n🧪"', start = input.indexOf('é'), end = input.lastIndexOf('"');
  const [valid] = withLocations(input, [{ start, end, type: 'client-id' }]);
  const invalid = [];
  for (const key of ['startLine', 'startColumn', 'endLine', 'endColumn']) {
    const missing = { ...valid }; delete missing[key]; invalid.push(missing);
    for (const value of [0, -1, 1.5, null, '2', Number.MAX_SAFE_INTEGER + 1, valid[key] + 1]) invalid.push({ ...valid, [key]: value });
  }
  for (const finding of [valid, ...invalid]) {
    const state = fixture(), result = state.api.redact(input);
    const rejected = finding === valid ? null : assert.rejects(result, { code: 'invalid' });
    state.reply({ ok: true, result: { text: input.slice(0, start) + 'xxxxxxxxxx' + input.slice(end), count: 1, findings: [finding] } });
    if (rejected) await rejected;
    else assert.deepEqual((await result).findings, [valid]);
    assert.equal(state.frames[0].removed, true);
    assert.equal(state.channels[0].port1.closed, true);
    assert.equal(state.timers.size, 0);
    const retry = state.api.redact('safe retry'); state.complete('safe retry');
    assert.equal((await retry).count, 0);
  }
});

test('worker spans cannot split a Unicode surrogate pair even with plausible coordinates', async () => {
  for (const [start, end] of [[0, 1], [1, 2]]) {
    const state = fixture(), result = state.api.redact('😀');
    const rejected = assert.rejects(result);
    state.reply({ ok: true, result: { text: '😀'.slice(0, start) + 'xxxxxxxxxx' + '😀'.slice(end), count: 1,
      findings: [{ start, end, type: 'test', startLine: 1, endLine: 1, startColumn: 1, endColumn: 4 }] } });
    await rejected;
    assert.equal(state.frames[0].removed, true);
    assert.equal(state.timers.size, 0);
  }
});
