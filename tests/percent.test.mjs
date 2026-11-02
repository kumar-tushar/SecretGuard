import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { scan, redact, MASK, ScanError } from '../src/index.mjs';
import { providerKey } from './fixtures/gitleaks-credentials.mjs';

const percent = text => [...Buffer.from(text)].map(byte => '%' + byte.toString(16).padStart(2, '0')).join('');
const base64 = text => Buffer.from(text).toString('base64');
const generic = 'N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8';
function check(input, values, expected, policy, options) {
  const result = redact(input, policy, input.length, options);
  assert.deepEqual(result.findings.map(item => input.slice(item.start, item.end)), values, input);
  assert.equal(result.count, values.length);
  assert.equal(result.text, expected);
  for (const item of result.findings) assert.deepEqual(Object.keys(item).sort(), [...(item.description === undefined ? [] : ['description']), 'end', 'endColumn', 'endLine', 'start', 'startColumn', 'startLine', ...(item.tags ? ['tags'] : []), 'type']);
  assert.deepEqual(scan(expected, policy, expected.length, options), [], 'masked text has no remaining findings');
  return result;
}

test('percent-encoded separators restore assignments while preserving original surrounding text', () => {
  for (const separator of ['%3D', '%3d', '%3A', '%3a']) {
    const text = `api_key${separator}${generic}`;
    assert.deepEqual(scan(text, undefined, text.length, { maxDecodeDepth: 0 }), []);
    check(text, [generic], `api_key${separator}${MASK}`);
  }
  for (const text of [providerKey, `api_key=${generic}`, `{"api_key":"${providerKey}"}`]) {
    const value = percent(text);
    check(`Before. ${value}\nAfter.`, [value], `Before. ${MASK}\nAfter.`);
    check(value.toUpperCase(), [value.toUpperCase()], MASK);
  }
});

test('URL values and partially encoded credentials retain exact original value bounds', () => {
  const encoded = generic.slice(0, 8) + percent(generic.slice(8, 15)) + generic.slice(15);
  const url = `https://example.invalid/?view=public&api_key=${encoded}`;
  check(url, [encoded], `https://example.invalid/?view=public&api_key=${MASK}`);
  const label = 'api%5Fkey', text = `${label}=${generic}`;
  check(text, [generic], `${label}=${MASK}`);
});

test('percent scanning preserves review modes, saved fields and the client-ID preference', () => {
  const custom = percent('dataset_key="short value"'), client = percent('client_id=demo-client-123');
  for (const mode of ['redact', 'block']) {
    check(custom, [], custom, { mode });
    check(custom, [custom], MASK, { mode, sensitiveNames: ['dataset_key'] });
    check(client, [client], MASK, { mode });
    check(client, [], client, { mode, protectClientIds: false });
    check(client, [client], MASK, { mode, protectClientIds: false, sensitiveNames: ['client_id'] });
  }
  assert.throws(() => scan(percent('dataset_key="unfinished'), { sensitiveNames: ['dataset_key'] }), ScanError);
});

test('invalid percent escapes remain literal and non-ASCII/binary escape candidates are skipped', () => {
  for (const suffix of ['%00', '%08', '%7F', '%80', '%FF', '%C3%A9']) {
    const value = percent(`api_key=${generic}`) + suffix;
    check(value, [], value);
    const good = percent(providerKey), input = `${value}\n${good}`;
    check(input, [good], `${value}\n${MASK}`);
  }
  for (const escape of ['%', '%2', '%GG', '%u003D']) {
    const value = `api_key${escape}${generic}`;
    check(value, [], value);
  }
  const label = 'notes=%31%GG ; api_key%3D', input = `${label}${generic}`;
  check(input, [generic], `${label}${MASK}`);
});

test('percent decoding retains entropy, exclusions and retired-heuristic negatives', () => {
  for (const value of ['api_key=xxxxxxxxxx', 'api_key=${SERVICE_KEY}', 'api_key=example7Yp3K9s6',
    'api_key=aabbccdd01234567', `api_key=${generic}&view=public`, 'key={day}', 'key={event.id}', 'client_id={event.id}',
    'api key\n\nhju867fggfgxxjgswrxl', 'Explain how API keys work.']) {
    const encoded = percent(value);
    check(encoded, [], encoded);
  }
});

test('mixed percent and Base64 layers share the same three-pass depth limit', () => {
  const paths = [[percent], [percent, percent], [base64, percent], [percent, base64],
    [percent, percent, percent], [percent, base64, percent], [base64, percent, base64],
    [base64, base64, percent], [percent, base64, base64]];
  for (const path of paths) {
    const value = path.reduce((text, encode) => encode(text), providerKey);
    for (let limit = 0; limit <= 3; limit++) {
      const detects = limit >= path.length;
      check(value, detects ? [value] : [], detects ? MASK : value, undefined, { maxDecodeDepth: limit });
    }
  }
  const deep = percent(base64(percent(base64(providerKey))));
  check(deep, [], deep);
});

test('Unicode context, independent lines and repeated occurrences keep UTF-16 bounds', () => {
  const first = percent(`api_key=${generic}`), second = base64(percent(providerKey));
  const harmless = percent('ordinary text');
  for (let i = 0; i < 50; i++) {
    const input = `😀 हिन्दी ${harmless}\n${first}\nclient_id=public-client-${i}\n${second}\n${first}\n尾`;
    const result = check(input, [first, `public-client-${i}`, second, first],
      `😀 हिन्दी ${harmless}\n${MASK}\nclient_id=${MASK}\n${MASK}\n${MASK}\n尾`);
    assert.equal(result.findings[0].start, input.indexOf(first));
    assert.equal(result.findings.at(-1).end, input.lastIndexOf(first) + first.length);
  }
});

test('mapping retains Gitleaks first-to-last escape boundaries across literals and nested layers', () => {
  const value = `%61${generic.slice(1)}; harmless=%20`, input = `api_key=${value}done`;
  check(input, [value], `api_key=${MASK}done`);
  let label = 'project_secret';
  for (let depth = 1; depth <= 3; depth++) {
    label = percent(label);
    const encoded = percent('inner-secret'), body = `prefix ${encoded} suffix`;
    // The line-wide percent candidate covers the encoded name and encoded value.
    const text = `😀 ${label}: "${body}"\nKeep.`;
    const original = text.slice(text.indexOf('%'), text.lastIndexOf('%') + 3);
    const result = check(text, [original + ' suffix'], `😀 ${MASK}"\nKeep.`, { sensitiveNames: ['project_secret'] });
    assert.equal(result.findings[0].start, text.indexOf('%'));
  }
});

test('plus signs are not form-decoded and ASCII line-break escapes retain surrounding context', () => {
  check('client%5Fid=hello+world', ['hello+world'], `client%5Fid=${MASK}`);
  for (const escape of ['%09', '%0A', '%0D%0A']) {
    const text = `api_key%3D${escape}${generic}`;
    check(text, [generic], `api_key%3D${escape}${MASK}`);
  }
  const text = `😀 %61pi_key%3D${generic}\nKeep this.`;
  check(text, [generic], `😀 %61pi_key%3D${MASK}\nKeep this.`);
});

test('percent encoding exercises every enabled rule without changing the rule catalog', async () => {
  const references = await Promise.all(['generic', 'providers', 'structured', 'curl', 'collaboration', 'catalog']
    .map(async name => JSON.parse(await readFile(new URL(`./fixtures/gitleaks-${name}.json`, import.meta.url), 'utf8'))));
  let checked = 0;
  for (const rule of SecretShieldRules.rules) {
    const item = rule.id === 'generic-api-key' ? { input: `api_key=${generic}` } :
      references.flatMap(value => value.cases).find(value => value.ruleId === rule.id && value.secrets.length && /^[\x09-\x7e]*$/.test(value.input));
    assert.ok(item, rule.id);
    const encoded = percent(item.input);
    check(encoded, [encoded], MASK);
    checked++;
  }
  assert.equal(checked, 217);
});

test('percent and mixed findings match the independently evaluated Gitleaks reference', async () => {
  const reference = JSON.parse(await readFile(new URL('./fixtures/gitleaks-percent.json', import.meta.url), 'utf8'));
  assert.equal(reference.cases.length, 48);
  for (const item of reference.cases) {
    const result = check(item.input, item.secrets, MASK);
    assert.ok(item.upstreamRules.includes(result.findings[0].type), item.name);
    assert.ok(item.decodedSecrets.length, item.name);
  }
});

test('percent parsing, shared budget exhaustion and long near matches finish in bounded subprocesses', () => {
  const script = `import assert from 'node:assert/strict';
    import {redact,ScanError} from './src/index.mjs';
    const huge='%5E'.repeat(1000001);
    assert.throws(()=>redact(huge,undefined,huge.length),ScanError);
    const nested='%255E'.repeat(600000);
    assert.throws(()=>redact(nested,undefined,nested.length),ScanError);
    const invalid='%00'+huge;
    assert.equal(redact(invalid,undefined,invalid.length).text,invalid);
    const near='%31'+'%gg'.repeat(200000)+' end';
    assert.equal(redact(near,undefined,near.length).text,near);
    const key=${JSON.stringify(providerKey)};
    const encoded=[...Buffer.from(key)].map(byte=>'%'+byte.toString(16).padStart(2,'0')).join('');
    const many=Array(10000).fill(encoded).join('\\n');
    assert.equal(redact(many,undefined,many.length).count,10000);`;
  execFileSync(process.execPath, ['--input-type=module', '-e', script],
    { cwd: new URL('..', import.meta.url), timeout: 10000, stdio: 'pipe' });
});
