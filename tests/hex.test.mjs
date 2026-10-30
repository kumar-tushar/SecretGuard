import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { scan, redact, MASK, ScanError } from '../src/index.mjs';
import { providerKey } from './fixtures/gitleaks-credentials.mjs';

const hex = text => Buffer.from(text).toString('hex');
const percent = text => [...Buffer.from(text)].map(byte => '%' + byte.toString(16).padStart(2, '0')).join('');
const base64 = text => Buffer.from(text).toString('base64');
const generic = 'N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8';
function check(input, values, expected, policy, options) {
  const result = redact(input, policy, input.length, options);
  assert.deepEqual(result.findings.map(item => input.slice(item.start, item.end)), values, input);
  assert.equal(result.count, values.length);
  assert.equal(result.text, expected);
  for (const item of result.findings) assert.deepEqual(Object.keys(item).sort(), item.tags ? ['end', 'start', 'tags', 'type'] : ['end', 'start', 'type']);
  assert.deepEqual(scan(expected, policy, expected.length, options), [], 'masked text has no remaining findings');
  return result;
}

test('hex blobs decode assignments and provider tokens in either character case', () => {
  for (const text of [providerKey, `api_key=${generic}`, `{"api_key":"${providerKey}"}`]) {
    for (const value of [hex(text), hex(text).toUpperCase()]) {
      assert.deepEqual(scan(value, undefined, value.length, { maxDecodeDepth: 0 }), []);
      check(`Before. ${value}\nAfter.`, [value], `Before. ${MASK}\nAfter.`);
    }
  }
});

test('hex candidates require 32 characters and complete pairs, with hex precedence over Base64', () => {
  const value = hex('client_id=123456');
  assert.equal(value.length, 32);
  check(value, [value], MASK);
  for (const short of [hex('client_id=12345'), value.slice(0, 31)]) check(short, [], short);
  for (const suffix of ['0', 'F']) check(hex(providerKey) + suffix, [], hex(providerKey) + suffix);
  // Hex has no Base64 padding. A following equals sign stays outside its span.
  check(hex(providerKey) + '=', [hex(providerKey)], MASK + '=');
});

test('partly encoded values keep surrounding labels, punctuation and original bounds', () => {
  const value = hex(generic), text = `😀 api_key="${value}"\nKeep this.`;
  check(text, [value], `😀 api_key="${MASK}"\nKeep this.`);
  const label = hex('client_id=123456');
  check(`[${label}], ${providerKey}`, [label, providerKey], `[${MASK}], ${MASK}`);
});

test('hex scanning preserves review modes, custom fields and client-ID settings', () => {
  const custom = hex('dataset_key="short value"'), client = hex('client_id=demo-client-123');
  for (const mode of ['redact', 'block']) {
    check(custom, [], custom, { mode });
    check(custom, [custom], MASK, { mode, sensitiveNames: ['dataset_key'] });
    check(client, [client], MASK, { mode });
    check(client, [], client, { mode, protectClientIds: false });
    check(client, [client], MASK, { mode, protectClientIds: false, sensitiveNames: ['client_id'] });
  }
  assert.throws(() => scan(hex('dataset_key="unfinished'), { sensitiveNames: ['dataset_key'] }), ScanError);
});

test('binary and non-ASCII hex candidates are rejected completely without hiding other lines', () => {
  for (const suffix of ['00', '08', '7F', '80', 'FF', 'C3A9']) {
    const bad = hex(`api_key=${generic}`) + suffix, good = hex(providerKey);
    check(bad, [], bad);
    check(`${bad}\n${good}`, [good], `${bad}\n${MASK}`);
  }
  for (const text of ['0'.repeat(32), 'a'.repeat(32), 'f'.repeat(32), hex('ordinary words without credentials'),
    hex(providerKey).match(/.{1,16}/g).join(' ')]) check(text, [], text);
});

test('hex decoding retains entropy, upstream exclusions and retired-heuristic negatives', () => {
  for (const value of ['api_key=xxxxxxxxxx', 'api_key=${SERVICE_KEY}', 'api_key=example7Yp3K9s6',
    'api_key=aabbccdd01234567', `api_key=${generic}&view=public`, 'key={day}', 'key={event.id}',
    'client_id={event.id}', 'api key\n\nhju867fggfgxxjgswrxl', 'Explain how API keys work.']) {
    const encoded = hex(value);
    check(encoded, [], encoded);
  }
});

test('hex, Base64 and percent nesting share the same three-pass limit', () => {
  const codecs = { H: hex, B: base64, P: percent };
  for (const route of ['H', 'HH', 'HHH', 'HB', 'BH', 'HP', 'PH', 'HBP', 'BPH', 'PHB', 'BHP', 'HPB', 'PBH']) {
    const value = [...route].reduce((text, codec) => codecs[codec](text), providerKey);
    for (let depth = 0; depth <= 3; depth++) {
      const detects = depth >= route.length;
      check(value, detects ? [value] : [], detects ? MASK : value, undefined, { maxDecodeDepth: depth });
    }
  }
  const deep = hex(base64(percent(hex(providerKey))));
  check(deep, [], deep);
});

test('Unicode, independent candidates and repeated occurrences map to UTF-16 source positions', () => {
  const first = hex(`api_key=${generic}`), second = base64(hex(providerKey)), harmless = hex('ordinary words only');
  for (let i = 0; i < 50; i++) {
    const input = `😀 हिन्दी ${harmless}\n${first}\nclient_id=public-client-${i}\n${second}\n${first}\n尾`;
    const result = check(input, [first, `public-client-${i}`, second, first],
      `😀 हिन्दी ${harmless}\n${MASK}\nclient_id=${MASK}\n${MASK}\n${MASK}\n尾`);
    assert.equal(result.findings[0].start, input.indexOf(first));
    assert.equal(result.findings.at(-1).end, input.lastIndexOf(first) + first.length);
  }
});

test('native and decoded overlaps mask the complete custom value and cross-segment span', () => {
  const value = `prefix ${hex('inner secret value')} suffix`, input = `dataset_key="${value}"`;
  check(input, [value], `dataset_key="${MASK}"`, { sensitiveNames: ['dataset_key'] });
  const name = hex('project_secret=12'), encoded = hex('inner secret value');
  // Decode the name and value in separate passes; the custom value still
  // includes its literal prefix and suffix when mapped back to the source.
  const text = `${percent('project_secret')}="prefix ${encoded} suffix"`;
  check(text, [`prefix ${encoded} suffix`], `${percent('project_secret')}="${MASK}"`, { sensitiveNames: ['project_secret'] });
  check(`${name}\n${hex('project_secret=12')}`, [name, name], `${MASK}\n${MASK}`, { sensitiveNames: ['project_secret'] });
});

test('hex-encoded ASCII whitespace and line breaks preserve assignments', () => {
  for (const space of ['\t', '\n', '\r\n']) {
    const value = hex(`api_key=${space}${generic}`);
    check(value, [value], MASK);
  }
  const value = hex('client_id="hello~world"');
  check(value, [value], MASK);
});

test('hex encoding exercises every enabled rule without changing the rule catalog', async () => {
  const references = await Promise.all(['generic', 'providers', 'structured', 'curl', 'collaboration', 'catalog']
    .map(async name => JSON.parse(await readFile(new URL(`./fixtures/gitleaks-${name}.json`, import.meta.url), 'utf8'))));
  let checked = 0;
  for (const rule of SecretShieldRules.rules) {
    const item = rule.id === 'generic-api-key' ? { input: `api_key=${generic}` } :
      references.flatMap(value => value.cases).find(value => value.ruleId === rule.id && value.secrets.length && /^[\x09-\x7e]*$/.test(value.input));
    assert.ok(item, rule.id);
    const encoded = hex(item.input);
    check(encoded, [encoded], MASK);
    checked++;
  }
  assert.equal(checked, 217);
});

test('hex and mixed findings match the independently evaluated Gitleaks reference', async () => {
  const reference = JSON.parse(await readFile(new URL('./fixtures/gitleaks-hex.json', import.meta.url), 'utf8'));
  assert.equal(reference.cases.length, 78);
  for (const item of reference.cases) {
    const result = check(item.input, item.secrets, MASK);
    assert.ok(item.upstreamRules.includes(result.findings[0].type), item.name);
    assert.ok(item.decodedSecrets.length, item.name);
  }
});

test('hex validation, shared budgets and many candidates finish in bounded subprocesses', () => {
  const script = `import assert from 'node:assert/strict';
    import {redact,ScanError} from './src/index.mjs';
    const huge='5e'.repeat(1000001);
    assert.throws(()=>redact(huge,undefined,huge.length),ScanError);
    const nested=Buffer.from('5e'.repeat(400000)).toString('hex');
    assert.throws(()=>redact(nested,undefined,nested.length),ScanError);
    const invalid='00'+huge;
    assert.equal(redact(invalid,undefined,invalid.length).text,invalid);
    const odd=huge+'0';
    assert.equal(redact(odd,undefined,odd.length).text,odd);
    const near='gg'.repeat(200000);
    assert.equal(redact(near,undefined,near.length).text,near);
    const encoded=Buffer.from(${JSON.stringify(providerKey)}).toString('hex');
    const many=Array(10000).fill(encoded).join('\\n');
    assert.equal(redact(many,undefined,many.length).count,10000);`;
  execFileSync(process.execPath, ['--input-type=module', '-e', script],
    { cwd: new URL('..', import.meta.url), timeout: 10000, stdio: 'pipe' });
});
