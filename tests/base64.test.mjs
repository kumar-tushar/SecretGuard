import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { scan, redact, MASK, ScanError } from '../src/index.mjs';
import { providerKey } from './fixtures/gitleaks-credentials.mjs';

const encode = (text, kind = 'base64') => Buffer.from(text).toString(kind);
const generic = 'N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8';
function check(input, values, expected, policy, options) {
  const result = redact(input, policy, input.length, options);
  assert.deepEqual(result.findings.map(item => input.slice(item.start, item.end)), values);
  assert.equal(result.count, values.length);
  assert.equal(result.text, expected);
  for (const item of result.findings) assert.deepEqual(Object.keys(item).sort(), [...(item.description === undefined ? [] : ['description']), 'end', 'endColumn', 'endLine', 'start', 'startColumn', 'startLine', ...(item.tags ? ['tags'] : []), 'type']);
  assert.deepEqual(scan(expected, policy, expected.length, options), [], 'masked text has no remaining findings');
  return result;
}

test('Base64 plaintext assignments, standalone provider keys and JSON mask the complete encoded segment', () => {
  for (const text of [providerKey, `api_key = ${generic}`, `{"api_key":"${providerKey}"}`]) {
    for (const suffix of ['', ' ', '  ']) for (const kind of ['base64', 'base64url']) {
      const encoded = encode(text + suffix, kind);
      for (const value of [encoded, encoded.replace(/=+$/, '')]) {
        const input = `Before: ${value}\nAfter.`;
        check(input, [value], `Before: ${MASK}\nAfter.`);
      }
    }
  }
});

test('decoded values use the original label, keyword context and rule exclusions', () => {
  const encoded = encode(generic);
  check(`api_key = ${encoded}`, [encoded], `api_key = ${MASK}`);
  check(`An ordinary value: ${encoded}`, [], `An ordinary value: ${encoded}`);
  for (const text of ['api_key=xxxxxxxxxx', 'api_key=${SERVICE_KEY}', 'api_key=example7Yp3K9s6',
    'api_key=aabbccdd01234567', 'key={event.id}', 'api key\n\nhju867fggfgxxjgswrxl']) {
    const value = encode(text);
    check(value, [], value);
  }
  const label = encode('client_secret');
  check(`${label}: ${generic}`, [generic], `${label}: ${MASK}`);
});

test('UTF-16 mapping preserves unchanged gaps, adjacent findings and repeated encoded occurrences', () => {
  const first = encode(providerKey), second = encode(`api_key=${generic}`);
  const harmless = encode('An ordinary paragraph with no credential.');
  const input = `😀 हिन्दी ${harmless}\n${first}; ${providerKey}\n${second}\n${first}\n尾`;
  const result = check(input, [first, providerKey, second, first],
    `😀 हिन्दी ${harmless}\n${MASK}; ${MASK}\n${MASK}\n${MASK}\n尾`);
  assert.equal(result.findings[0].start, input.indexOf(first));
  assert.equal(result.findings.at(-1).end, input.lastIndexOf(first) + first.length);
});

test('findings spanning two decoded segments include their complete original bounds', () => {
  const user = encode('service-user'), password = encode(generic);
  const pair = `"${user}:${password}"`, input = `curl -u ${pair} https://example.invalid`;
  const result = check(input, [pair], 'curl -u xxxxxxxxxx https://example.invalid');
  assert.equal(result.findings[0].type, 'curl-auth-user');
  let label = 'project_secret';
  for (let depth = 1; depth <= 3; depth++) {
    label = encode(label);
    const inner = encode('inner-secret-value'), value = `prefix ${inner} suffix`;
    const text = `😀 ${label}: "${value}"\nKeep this.`, policy = { sensitiveNames: ['project_secret'] };
    assert.deepEqual(scan(text, policy, text.length, { maxDecodeDepth: 0 }), [], 'only the decoded label enables this cross-segment finding');
    const mapped = check(text, [value], `😀 ${label}: "${MASK}"\nKeep this.`, policy);
    assert.equal(mapped.findings[0].start, text.indexOf(value));
  }
});

test('nested Base64 scanning maps through three passes and honors the explicit depth limit', () => {
  let value = providerKey;
  for (let depth = 1; depth <= 4; depth++) {
    value = encode(value);
    for (let limit = 0; limit <= 3; limit++) {
      const detects = depth <= limit;
      check(`😀 ${value} end.`, detects ? [value] : [], `😀 ${detects ? MASK : value} end.`, undefined, { maxDecodeDepth: limit });
    }
    if (depth <= 3) check(value, [value], MASK);
    else check(value, [], value);
  }
  for (const options of [null, [], 2, { maxDecodeDepth: null }, { maxDecodeDepth: -1 },
    { maxDecodeDepth: 4 }, { maxDecodeDepth: 1.5 }, { maxDecodeDepth: '1' }, { maxDecodeDepth: Infinity }]) {
    assert.throws(() => scan(value, undefined, value.length, options), ScanError);
  }
});

test('custom fields and the client-ID preference also apply inside decoded text', () => {
  const custom = encode('dataset_key="short value"'), client = encode('client_id=demo-client-123');
  check(custom, [], custom);
  check(custom, [custom], MASK, { sensitiveNames: ['dataset_key'] });
  check(client, [client], MASK);
  check(client, [], client, { protectClientIds: false });
  check(client, [client], MASK, { protectClientIds: false, sensitiveNames: ['client_id'] });
  const unfinished = encode('dataset_key="unfinished');
  assert.throws(() => scan(unfinished, { sensitiveNames: ['dataset_key'] }), ScanError);
  check(unfinished, [], unfinished);
  check(encode('dataset_key={event.id}'), [], encode('dataset_key={event.id}'), { sensitiveNames: ['dataset_key'] });
});

test('malformed padding, noncanonical final bits, binary and non-ASCII data are not partially decoded', () => {
  const encoded = encode(`api_key=${generic}`), padded = encode(providerKey);
  assert.match(padded, /==$/);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const index = padded.length - 3;
  const noncanonical = padded.slice(0, index) + alphabet[alphabet.indexOf(padded[index]) + 1] + '==';
  for (const value of [encoded + '===', encoded + '=', encoded.slice(0, -3) + '===', noncanonical,
    encode(`api_key=${generic}\u0000`), encode(`😀 api_key=${generic}`), 'A'.repeat(17), 'x'.repeat(100)]) {
    check(value, [], value);
  }
});

test('both Base64 alphabets decode without browser APIs and reject mixed alphabets', () => {
  const content = `api_key=${generic}; >>>???`, standard = encode(content), url = encode(content, 'base64url');
  assert.match(standard, /[+/]/);
  assert.match(url, /[-_]/);
  check(standard, [standard], MASK);
  check(url, [url], MASK);
  const mixed = standard.replace('+', '-');
  assert.match(mixed, /[-_]/);
  assert.match(mixed, /[+/]/);
  check(mixed, [], mixed);
});

test('decoded findings preserve all enabled rule families without changing the catalog', async () => {
  const references = await Promise.all(['generic', 'providers', 'structured', 'curl', 'collaboration', 'catalog']
    .map(async name => JSON.parse(await readFile(new URL(`./fixtures/gitleaks-${name}.json`, import.meta.url), 'utf8'))));
  let checked = 0;
  for (const rule of SecretShieldRules.rules) {
    const fixture = rule.id === 'generic-api-key' ? { input: `api_key=${generic}` } :
      references.flatMap(value => value.cases).find(value => value.ruleId === rule.id && value.secrets.length && /^[\x09-\x7e]*$/.test(value.input));
    assert.ok(fixture, rule.id);
    const encoded = encode(fixture.input);
    const result = check(encoded, [encoded], MASK);
    assert.ok(result.findings.length, rule.id);
    checked++;
  }
  assert.equal(checked, 217);
});

test('seeded nested and mixed drafts keep independent source spans and deterministic masks', () => {
  for (let i = 0; i < 100; i++) {
    let secret = encode(`api_key=${providerKey}\n${'keep '.repeat(i % 9)}`);
    for (let depth = 0; depth < i % 3; depth++) secret = encode(secret);
    const harmless = encode(`Public example ${i}: do not change this paragraph.`);
    const input = `🛡️ ${harmless}\n${secret}\nclient_id=public-client-${i}\n${secret}\n${harmless}`;
    check(input, [secret, `public-client-${i}`, secret], `🛡️ ${harmless}\n${MASK}\nclient_id=${MASK}\n${MASK}\n${harmless}`);
  }
});

test('Base64 findings match the independently evaluated Gitleaks decoding reference', async () => {
  const reference = JSON.parse(await readFile(new URL('./fixtures/gitleaks-base64.json', import.meta.url), 'utf8'));
  assert.equal(reference.cases.length, 36);
  for (const item of reference.cases) {
    const result = check(item.input, item.secrets, MASK);
    assert.ok(item.upstreamRules.includes(result.findings[0].type), item.name);
    assert.ok(item.decodedSecrets.length, item.name);
  }
});

test('large valid payloads and exhausted decoding budgets finish in bounded subprocesses', () => {
  const script = `import assert from 'node:assert/strict';
    import {redact,ScanError} from './src/index.mjs';
    const key=${JSON.stringify(providerKey)};
    const plain='ordinary text. '.repeat(10000)+'\\n'+key;
    const encoded=Buffer.from(plain).toString('base64');
    assert.equal(redact(encoded,undefined,encoded.length).text,'xxxxxxxxxx');
    const huge=Buffer.from('^'.repeat(1000001)).toString('base64');
    assert.throws(()=>redact(huge,undefined,huge.length),ScanError);
    const many=Array(20000).fill(Buffer.from(key).toString('base64')).join('\\n');
    assert.equal(redact(many,undefined,many.length).count,20000);`;
  execFileSync(process.execPath, ['--input-type=module', '-e', script],
    { cwd: new URL('..', import.meta.url), timeout: 10000, stdio: 'pipe' });
});
