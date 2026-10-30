import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { scan, redact, MASK, MAX_CHARACTERS, ScanError } from '../src/index.mjs';

const reference = JSON.parse(await readFile(new URL('./fixtures/gitleaks-structured.json', import.meta.url), 'utf8'));
const providers = JSON.parse(await readFile(new URL('./fixtures/gitleaks-providers.json', import.meta.url), 'utf8')).examples;
const core = await readFile(new URL('../src/core.js', import.meta.url), 'utf8');
const key = reference.examples['private-key'][0], jwt = reference.examples.jwt[0];

for (const id of ['private-key', 'jwt']) test(`${id} matches the independently evaluated Gitleaks reference`, () => {
  const context = vm.createContext({ SecretShieldRules: { ...SecretShieldRules, rules: SecretShieldRules.rules.filter(rule => rule.id === id) } });
  vm.runInContext(core, context);
  for (const fixture of reference.cases.filter(item => item.ruleId === id)) {
    const findings = context.SecretShieldCore.scan(fixture.input, undefined, undefined, { maxDecodeDepth: 0 });
    assert.deepEqual(Array.from(findings, item => fixture.input.slice(item.start, item.end)), fixture.secrets, fixture.name);
    let cursor = 0, expected = '';
    for (const finding of findings) {
      assert.equal(finding.type, id);
      assert.deepEqual(Object.keys(finding).sort(), ['end', 'start', 'type']);
      assert.ok(finding.start >= cursor && finding.end > finding.start && finding.end <= fixture.input.length);
      expected += fixture.input.slice(cursor, finding.start) + MASK;
      cursor = finding.end;
    }
    expected += fixture.input.slice(cursor);
    assert.equal(context.SecretShieldCore.redact(fixture.input, undefined, undefined, { maxDecodeDepth: 0 }).text, expected, fixture.name);
    assert.equal(context.SecretShieldCore.scan(expected, undefined, undefined, { maxDecodeDepth: 0 }).length, 0, fixture.name);
  }
});

test('private-key length constraints count code points while findings retain UTF-16 offsets', () => {
  const prefix = '-----BEGIN PRIVATE KEY-----', suffix = 'KEY-----';
  for (const char of ['A', '🧪', '\u00a0', '\u2028']) {
    assert.deepEqual(scan(prefix + char.repeat(63) + suffix), [], char);
    const block = prefix + char.repeat(64) + suffix, text = `🛡️ हिन्दी ${block}\nKeep this.`;
    const start = text.indexOf(prefix);
    assert.deepEqual(scan(text), [{ start, end: start + block.length, type: 'private-key' }]);
    assert.equal(redact(text).text, '🛡️ हिन्दी xxxxxxxxxx\nKeep this.');
  }
});

test('multiline blocks and standalone signed or unsigned JWTs are masked without nearby field names', () => {
  for (const [type, values] of Object.entries(reference.examples)) for (const value of values) {
    for (const mode of ['redact', 'block']) {
      const text = `Keep this header.\n\n${value}\n\nKeep this footer.`;
      const start = text.indexOf(value);
      assert.deepEqual(scan(text, { mode }), [{ start, end: start + value.length, type }]);
      assert.equal(redact(text, { mode }).text, `Keep this header.\n\n${MASK}\n\nKeep this footer.`);
      assert.ok(!JSON.stringify(scan(text, { mode })).includes(value));
    }
  }
});

test('private blocks absorb contained generic, provider and JWT findings exactly once', () => {
  const nested = `-----BEGIN PRIVATE KEY-----\napi_key=${providers['github-pat'][0]}\n${jwt}\n-----END PRIVATE KEY-----`;
  const text = `Before\n${nested}\n${key}\n${jwt}\nAfter`;
  const result = redact(text);
  assert.equal(result.count, 3);
  assert.deepEqual(result.findings.map(item => item.type), ['private-key', 'private-key', 'jwt']);
  assert.deepEqual(result.findings.map(item => text.slice(item.start, item.end)), [nested, key, jwt]);
  assert.equal(result.text, `Before\n${MASK}\n${MASK}\n${MASK}\nAfter`);
  assert.equal(scan(result.text).length, 0);
  const labeled = `token="${jwt}"`;
  assert.equal(redact(labeled).count, 1);
  assert.equal(redact(labeled).text, `token="${MASK}"`);
});

test('public blocks, incomplete private blocks and malformed tokens retain upstream scope', () => {
  for (const text of [key.replaceAll('PRIVATE KEY', 'PUBLIC KEY'), key.replaceAll('PRIVATE KEY', 'CERTIFICATE'),
    key.split('-----END')[0], '-----BEGIN PRIVATE KEY-----\nshort\n-----END PRIVATE KEY-----',
    'Explain JSON Web Tokens and private keys.', 'eyabc.eydef.signature',
    'key={event.id}', 'const row = {day};',
    'api_key\n\nhju867fggfgxxjgswrxl']) {
    assert.deepEqual(scan(text), [], text);
    assert.equal(redact(text).text, text);
  }
  const policy = { sensitiveNames: ['dataset_name'], protectClientIds: true };
  assert.equal(redact('dataset_name=Q7mV8z2R9tA4nP6xL3cD', policy).text, 'dataset_name=' + MASK);
  const wrapped = Buffer.from(jwt).toString('base64');
  assert.deepEqual(scan(wrapped), [{ start: 0, end: wrapped.length, type: 'jwt-base64', tags: ['decoded:base64', 'decode-depth:1'] }]);
  assert.equal(redact(wrapped).text, MASK);
});

test('complete large drafts, repeated multiline blocks and near matches stay deterministic', { timeout: 10000 }, () => {
  const text = 'Plain explanation.\n'.repeat(10000) + key + '\n' + jwt;
  assert.throws(() => scan(text), ScanError);
  for (let i = 0; i < 5; i++) {
    const result = redact(text, undefined, text.length);
    assert.equal(result.text, text.replace(key, MASK).replace(jwt, MASK));
    assert.equal(result.count, 2);
    assert.deepEqual(scan('Ordinary text.'), []);
  }
  const repeated = Array(100).fill(key + '\n' + jwt).join('\n');
  assert.equal(redact(repeated).count, 200);
  assert.equal(redact(repeated).text, Array(100).fill(MASK + '\n' + MASK).join('\n'));
  const near = '-----BEGIN '.repeat(5000) + ' A'.repeat(10000) + '\ney' + 'A'.repeat(20000) + '.';
  assert.deepEqual(scan(near, undefined, near.length), []);
  assert.equal(redact('a'.repeat(MAX_CHARACTERS)).count, 0);
});
