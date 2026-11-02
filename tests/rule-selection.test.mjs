import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { scan, redact, ScanError, MASK } from '../src/index.mjs';
import { providerKey } from './fixtures/gitleaks-credentials.mjs';

const core = await readFile(new URL('../src/core.js', import.meta.url), 'utf8');
const metadata = JSON.parse(await readFile(new URL('./fixtures/gitleaks-metadata.json', import.meta.url), 'utf8')).metadata;
const reference = JSON.parse(await readFile(new URL('./fixtures/gitleaks-rule-selection.json', import.meta.url), 'utf8'));
const policy = { protectClientIds: false };
const select = (text, ruleIds, settings = policy, options = {}) => redact(text, settings, text.length, { ...options, ruleIds });
const rule = (id, regex, extra = {}) => ({ id, regex, secretGroup: 1, entropy: 0, keywords: [], allowlists: [], ...extra });
function fixture(rules, globalAllowlists = []) {
  const source = { rules, globalAllowlists }, context = vm.createContext({ SecretShieldRules: source });
  vm.runInContext(core, context);
  return { source, api: context.SecretShieldCore, scan: (text, ruleIds) =>
    JSON.parse(JSON.stringify(context.SecretShieldCore.scan(text, policy, text.length, { ruleIds }))) };
}

test('omitted, undefined, empty and all-ID selections preserve default findings for all 217 catalog examples', () => {
  const ids = SecretShieldRules.rules.map(rule => rule.id);
  assert.equal(ids.length, 217);
  for (const { input } of Object.values(metadata)) {
    const expected = redact(input, policy);
    for (const selection of [undefined, [], ids, [...ids].reverse()]) assert.deepEqual(select(input, selection), expected);
  }
});

test('each of the 217 rules can be selected independently with its description, locations and spans', () => {
  for (const [id, { input, description }] of Object.entries(metadata)) {
    const result = select(input, [id], policy, { maxDecodeDepth: 0 });
    assert.ok(result.count > 0, id);
    for (const item of result.findings) {
      assert.equal(item.type, id);
      assert.equal(item.description, description);
      assert.ok(item.startLine > 0 && item.startColumn > 0 && item.endLine >= item.startLine && item.endColumn > 0);
      assert.ok(input.slice(item.start, item.end));
    }
  }
});

test('selection suppresses other rules, preserves overlapping selected rules and ignores caller order and duplicates', () => {
  const input = `api_key=${providerKey}\napi_key=N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8`;
  assert.deepEqual(select(input, ['github-pat']).findings.map(item => item.type), ['github-pat']);
  assert.deepEqual(select(input, ['generic-api-key']).findings.map(item => item.type), ['generic-api-key', 'generic-api-key']);
  const both = select(input, ['github-pat', 'generic-api-key']);
  assert.deepEqual(both.findings.map(item => item.type), ['github-pat', 'generic-api-key']);
  assert.deepEqual(select(input, ['generic-api-key', 'github-pat', 'github-pat']), both);
  assert.deepEqual(select(input, ['curl-auth-user']), { text: input, count: 0, findings: [] });
  assert.deepEqual(scan(input, policy, input.length, { ruleIds: ['github-pat'] }), select(input, ['github-pat']).findings);
});

test('malformed, unknown, excluded and case-mismatched IDs fail closed even on empty or harmless input', () => {
  const invalid = [null, false, 1, 'github-pat', {}, new Set(['github-pat']), [''], [' github-pat'], ['GITHUB-PAT'],
    ['github-pat', 'not-a-rule'], ['client-id'], ['custom-field'], ['pkcs12-file'], [undefined], [null], [1],
    Array(1), Array(1001).fill('github-pat')];
  for (const input of ['', 'ordinary', providerKey]) for (const ruleIds of invalid) {
    assert.throws(() => select(input, ruleIds), ScanError);
  }
  assert.equal(select(providerKey, Array(1000).fill('github-pat')).count, 1);
  assert.equal(select(providerKey, ['github-pat']).count, 1, 'invalid scans do not poison a subsequent scan');
});

test('selection applies to all codecs and shared decode depths using original spans and canonical tags', () => {
  const encoders = [text => Buffer.from(text).toString('base64'), text => Buffer.from(text).toString('hex'),
    text => [...Buffer.from(text)].map(byte => '%' + byte.toString(16).padStart(2, '0')).join('')];
  for (const encode of encoders) {
    const encoded = encode(providerKey), input = `Heading\n😀 ${encoded}\nKeep.`;
    const result = select(input, ['github-pat']);
    assert.equal(result.count, 1);
    assert.equal(result.text, `Heading\n😀 ${MASK}\nKeep.`);
    assert.equal(result.findings[0].type, 'github-pat');
    assert.ok(result.findings[0].tags.includes('decode-depth:1'));
    assert.equal(select(input, ['curl-auth-user']).count, 0);
    assert.equal(select(input, ['github-pat'], policy, { maxDecodeDepth: 0 }).count, 0);
  }
  const nested = encoders[0](encoders[2](encoders[1](providerKey)));
  assert.equal(select(nested, ['github-pat'], policy, { maxDecodeDepth: 2 }).count, 0);
  assert.deepEqual(select(nested, ['github-pat']).findings[0].tags,
    ['decoded:percent', 'decoded:hex', 'decoded:base64', 'decode-depth:3']);
});

test('custom fields and the client-ID preference remain independent of Gitleaks rule selection', () => {
  const input = `dataset_key=short\nclient_id=public-client-id\n${providerKey}`;
  const settings = { sensitiveNames: ['dataset_key'], protectClientIds: true };
  assert.deepEqual(select(input, ['curl-auth-user'], settings).findings.map(item => item.type), ['custom-field', 'client-id']);
  assert.deepEqual(select(input, ['github-pat'], { ...settings, protectClientIds: false }).findings.map(item => item.type), ['custom-field', 'github-pat']);
  assert.deepEqual(select(input, ['github-pat'], settings).findings.map(item => item.type), ['custom-field', 'client-id', 'github-pat']);
});

test('per-scan selection does not mutate defaults, source rules, policy, caller arrays or cached rule metadata', () => {
  const before = JSON.stringify(SecretShieldRules), settings = Object.freeze({ protectClientIds: false });
  const ids = Object.freeze(['github-pat', 'github-pat']);
  assert.equal(select(providerKey, ids, settings).count, 1);
  assert.equal(select(providerKey, ['curl-auth-user'], settings).count, 0);
  assert.equal(redact(providerKey, settings).count, 1);
  assert.equal(select(providerKey, [], settings).count, 1);
  assert.equal(JSON.stringify(SecretShieldRules), before);
  assert.deepEqual(ids, ['github-pat', 'github-pat']);
});

test('selected rules keep global, local and targeted shared allowlists without affecting other checks', () => {
  const allowlist = { regexes: ['^ALLOWED$'], stopwords: [], paths: [] };
  const { scan } = fixture([rule('first', 'first=([A-Z]+)', { allowlists: [allowlist] }), rule('second', 'second=([A-Z]+)')],
    [{ ...allowlist, targetRules: ['second'] }, { ...allowlist, regexes: ['^GLOBAL$'] }]);
  const input = 'first=ALLOWED first=GLOBAL first=RETAINED second=ALLOWED second=GLOBAL second=RETAINED';
  assert.deepEqual(scan(input, ['first']).map(item => input.slice(item.start, item.end)), ['RETAINED']);
  assert.deepEqual(scan(input, ['second']).map(item => input.slice(item.start, item.end)), ['RETAINED']);
  assert.deepEqual(scan(input, []).map(item => item.type), ['first', 'second']);
});

test('composite primaries require their supporting IDs to be explicitly selected in the same pass', () => {
  const { scan } = fixture([rule('primary', 'credential=([A-Z0-9]+)', { required: [{ id: 'support' }] }),
    rule('support', '(SERVICE)', { skipReport: true }), rule('other', '(REGION)')]);
  const input = 'SERVICE credential=ABC123 REGION';
  assert.deepEqual(scan(input, ['primary']), []);
  assert.deepEqual(scan(input, ['support']), []);
  assert.deepEqual(scan(input, ['primary', 'support']).map(item => item.type), ['primary']);
  assert.deepEqual(scan(input, []).map(item => item.type), ['primary', 'other']);
  const encoded = Buffer.from(input).toString('base64');
  assert.deepEqual(scan(encoded, ['primary']), []);
  assert.equal(scan(encoded, ['primary', 'support'])[0].type, 'primary');
});

test('selection preserves full-catalog validation and fails closed for broken unselected rules or references', () => {
  for (const extra of [rule('broken', '('), rule('broken', '(OK)', { required: [{ id: 'missing' }] })]) {
    const { api } = fixture([rule('selected', '(OK)'), extra]);
    assert.throws(() => api.scan('', policy, 0, { ruleIds: ['selected'] }), { name: 'Error' });
  }
});

test('selection matches 22 independent official Gitleaks scans including empty, duplicate, encoded and composite cases', () => {
  assert.equal(reference.cases.length, 22);
  for (const item of reference.cases) {
    const run = () => item.rules ? fixture(item.rules).scan(item.input, item.ruleIds) :
      scan(item.input, policy, item.input.length, { ruleIds: item.ruleIds });
    if (item.error) { assert.throws(run, ScanError, item.name); continue; }
    const actual = run().map(finding => ({ type: finding.type, secret: item.input.slice(finding.start, finding.end) }))
      .sort((a, b) => a.type.localeCompare(b.type) || a.secret.localeCompare(b.secret));
    assert.deepEqual(actual, item.findings, item.name);
  }
});
