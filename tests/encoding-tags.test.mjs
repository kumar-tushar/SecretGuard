import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { scan, redact, MASK } from '../src/index.mjs';
import { providerKey } from './fixtures/gitleaks-credentials.mjs';
import { withLocations } from './fixtures/finding-locations.mjs';

const codecs = {
  base64: text => Buffer.from(text).toString('base64'),
  hex: text => Buffer.from(text).toString('hex'),
  percent: text => [...Buffer.from(text)].map(byte => '%' + byte.toString(16).padStart(2, '0')).join(''),
};
const encode = (text, route) => route.reduce((value, kind) => codecs[kind](value), text);
const tags = (route, depth = route.length) => [...['percent', 'hex', 'base64'].filter(kind => route.includes(kind)).map(kind => `decoded:${kind}`), `decode-depth:${depth}`];

test('plaintext findings include their rule description without encoding or depth tags', () => {
  const input = `api_key=${providerKey}`, start = input.indexOf(providerKey);
  assert.deepEqual(scan(input), withLocations(input, [{ start, end: input.length, type: 'github-pat', description: SecretShieldRules.rules.find(rule => rule.id === 'github-pat').description }]));
  for (const route of [['base64'], ['hex'], ['percent']]) {
    const unrelated = encode('ordinary text without credentials', [...route, ...route, ...route]);
    const result = scan(input + '\n' + unrelated);
    assert.equal(result.length, 1);
    assert.equal(Object.hasOwn(result[0], 'tags'), false);
  }
});

test('single and repeated codec layers report unique encoding tags and their decode depth', () => {
  for (const kind of Object.keys(codecs)) for (let depth = 1; depth <= 3; depth++) {
    const route = Array(depth).fill(kind), encoded = encode(providerKey, route);
    const input = `😀 ${encoded}\nKeep.`, result = redact(input);
    assert.deepEqual(result.findings, withLocations(input, [{ start: 3, end: 3 + encoded.length, type: 'github-pat', description: SecretShieldRules.rules.find(rule => rule.id === 'github-pat').description, tags: tags(route) }]));
    assert.equal(result.text, `😀 ${MASK}\nKeep.`);
  }
});

test('mixed nested codecs use stable upstream tag order and a single maximum depth', () => {
  for (const route of [
    ['hex', 'base64'], ['percent', 'hex'], ['base64', 'percent'],
    ['hex', 'percent', 'base64'], ['base64', 'hex', 'percent'], ['percent', 'base64', 'hex'],
    ['hex', 'hex', 'percent'], ['base64', 'percent', 'base64'],
  ]) {
    const encoded = encode(providerKey, route), result = scan(encoded);
    assert.equal(result.length, 1);
    assert.deepEqual(result[0].tags, tags(route));
  }
});

test('independent findings keep their own codecs and depth during later decoding passes', () => {
  const routes = [['hex'], ['percent', 'percent'], ['hex', 'percent', 'base64']];
  const values = routes.map(route => encode(providerKey, route));
  const input = [providerKey, ...values, providerKey].join('\n'), result = redact(input);
  assert.deepEqual(result.findings.map(item => input.slice(item.start, item.end)), [providerKey, ...values, providerKey]);
  assert.deepEqual(result.findings.map(item => item.tags), [undefined, ...routes.map(route => tags(route)), undefined]);
  assert.equal(result.text, Array(5).fill(MASK).join('\n'));
});

test('a finding crossing independent decoded segments combines codecs without adding their depths', () => {
  const user = codecs.hex('service-username-1'), password = codecs.base64('N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8');
  const value = `"${user}:${password}"`, input = `curl -u ${value} https://example.invalid`;
  const result = redact(input);
  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0].tags, ['decoded:hex', 'decoded:base64', 'decode-depth:1']);
  assert.equal(input.slice(result.findings[0].start, result.findings[0].end), value);
  assert.equal(result.text, `curl -u ${MASK} https://example.invalid`);
});

test('encoded labels alone do not mark unchanged plaintext values as decoded', () => {
  const value = 'short-readable', policy = { sensitiveNames: ['project_secret'] };
  for (const name of [codecs.base64('project_secret'), codecs.percent('project_secret')]) {
    const input = `${name}: "${value}"`, result = scan(input, policy);
    assert.equal(result.length, 1);
    assert.equal(input.slice(result[0].start, result[0].end), value);
    assert.equal(result[0].tags, undefined);
  }
});

test('merged native and decoded findings retain codecs and the deepest contributing pass', () => {
  const value = encode(providerKey, ['hex', 'base64']), input = `project_secret="${value}"`;
  const result = redact(input, { sensitiveNames: ['project_secret'] });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].type, 'github-pat');
  assert.deepEqual(result.findings[0].tags, ['decoded:hex', 'decoded:base64', 'decode-depth:2']);
  assert.equal(result.text, `project_secret="${MASK}"`);
});

test('percent provenance uses the same coarse original span as masking', () => {
  const encoded = `%67${providerKey.slice(1)}; harmless=%20`, input = `😀 ${encoded}\nKeep.`;
  const result = redact(input);
  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0].tags, ['decoded:percent', 'decode-depth:1']);
  assert.equal(input.slice(result.findings[0].start, result.findings[0].end), encoded);
  assert.equal(result.text, `😀 ${MASK}\nKeep.`);
});

test('custom fields and client-ID preferences retain tags in either review mode', () => {
  const route = ['hex', 'percent', 'base64'];
  for (const mode of ['redact', 'block']) {
    const custom = encode('dataset_key="short value"', route), client = encode('client_id=demo-client-123', route);
    assert.deepEqual(scan(custom, { mode, sensitiveNames: ['dataset_key'] })[0].tags, tags(route));
    assert.deepEqual(scan(client, { mode })[0].tags, tags(route));
    assert.deepEqual(scan(client, { mode, protectClientIds: false }), []);
    assert.deepEqual(scan(client, { mode, protectClientIds: false, sensitiveNames: ['client_id'] })[0].tags, tags(route));
  }
});

test('decoding disabled or invalid input does not create encoding metadata', () => {
  const encoded = codecs.hex(providerKey);
  assert.deepEqual(scan(encoded, undefined, undefined, { maxDecodeDepth: 0 }), []);
  for (const input of [encoded + '0', encoded + '00', codecs.percent('api_key=xxxxxxxxxx')]) assert.deepEqual(scan(input), []);
});

test('all 162 encoded reference cases retain independently evaluated Gitleaks tags', async () => {
  let checked = 0;
  for (const codec of Object.keys(codecs)) {
    const reference = JSON.parse(await readFile(new URL(`./fixtures/gitleaks-${codec}.json`, import.meta.url), 'utf8'));
    for (const item of reference.cases) {
      const result = redact(item.input);
      assert.equal(result.findings.length, 1, item.name);
      assert.deepEqual(result.findings[0].tags, item.upstreamTags, item.name);
      assert.equal(result.text, MASK, item.name);
      checked++;
    }
  }
  assert.equal(checked, 162);
});

test('returned tags are independent between occurrences and scans and contain no decoded values', () => {
  const encoded = codecs.hex(providerKey), input = `${encoded}\n${encoded}`;
  const first = scan(input);
  first[0].tags.push('caller-change');
  assert.deepEqual(first[1].tags, ['decoded:hex', 'decode-depth:1']);
  const next = scan(input);
  assert.deepEqual(next.map(item => item.tags), [tags(['hex']), tags(['hex'])]);
  for (const item of next) assert.deepEqual(Object.keys(item).sort(), ['description', 'end', 'endColumn', 'endLine', 'start', 'startColumn', 'startLine', 'tags', 'type']);
  assert.equal(JSON.stringify(next).includes(providerKey), false);
});

test('many encoded findings keep provenance bounded and do not inflate depth', () => {
  const script = `import assert from 'node:assert/strict'; import {redact} from './src/index.mjs';
    const encoded=Buffer.from(${JSON.stringify(providerKey)}).toString('hex');
    const text=Array(10000).fill(encoded).join('\\n');
    const result=redact(text,undefined,text.length);
    assert.equal(result.count,10000);
    for(const item of result.findings) assert.deepEqual(item.tags,['decoded:hex','decode-depth:1']);`;
  execFileSync(process.execPath, ['--input-type=module', '-e', script],
    { cwd: new URL('..', import.meta.url), timeout: 10000, stdio: 'pipe' });
});
