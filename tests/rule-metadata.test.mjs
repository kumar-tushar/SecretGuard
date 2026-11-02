import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { scan, redact, MASK } from '../src/index.mjs';
import { providerKey } from './fixtures/gitleaks-credentials.mjs';
import { withLocations } from './fixtures/finding-locations.mjs';

const core = await readFile(new URL('../src/core.js', import.meta.url), 'utf8');
const reference = JSON.parse(await readFile(new URL('./fixtures/gitleaks-metadata.json', import.meta.url), 'utf8'));
const message = 'This text could not be scanned. Keep it local and shorten it before retrying.';
const rule = extra => ({ id: 'fixture-metadata', regex: 'credential=([A-Z][A-Z0-9]{5,})', secretGroup: 1, entropy: 0,
  keywords: [], allowlists: [], ...extra });
function fixture(rules) {
  const source = JSON.parse(JSON.stringify(SecretShieldRules));
  source.rules = rules;
  const context = vm.createContext({ SecretShieldRules: source });
  vm.runInContext(core, context);
  return { source, api: context.SecretShieldCore,
    scan: (text, policy, options) => JSON.parse(JSON.stringify(context.SecretShieldCore.scan(text, policy, text.length, options))) };
}

test('all 217 descriptions and default rule tags match the pinned catalog and official findings', () => {
  assert.equal(Object.keys(reference.metadata).length, 217);
  assert.equal(SecretShieldRules.rules.length, 217);
  for (const rule of SecretShieldRules.rules) {
    const expected = reference.metadata[rule.id];
    assert.equal(rule.description, expected.description, rule.id);
    assert.deepEqual(rule.tags ?? [], expected.tags, rule.id);
    const findings = fixture([rule]).scan(expected.input, { protectClientIds: false }, { maxDecodeDepth: 0 });
    assert.ok(findings.length, rule.id);
    for (const finding of findings) {
      assert.equal(finding.type, rule.id);
      assert.equal(finding.description, expected.description, rule.id);
      assert.equal(finding.tags, undefined, rule.id);
    }
  }
});

test('all 28 configured metadata cases match official plaintext, decoded and composite findings', () => {
  assert.equal(reference.cases.length, 28);
  for (const item of reference.cases) {
    const result = fixture(item.rules).scan(item.input, { protectClientIds: false });
    assert.equal(result.length, 1, item.name);
    assert.equal(result[0].type, 'fixture-metadata', item.name);
    assert.equal(result[0].description, item.rules[0].description === undefined ? undefined : item.description, item.name);
    assert.deepEqual(result[0].tags ?? [], item.tags, item.name);
    assert.deepEqual(Object.keys(result[0]).sort(), ['start', 'end', 'type', 'startLine', 'startColumn', 'endLine', 'endColumn',
      ...(result[0].description === undefined ? [] : ['description']), ...(item.tags.length ? ['tags'] : [])].sort());
  }
});

test('selected provider metadata replaces overlapping generic and explicit-field metadata', () => {
  const rules = ['generic-api-key', 'github-pat'].map(id => ({ ...SecretShieldRules.rules.find(rule => rule.id === id), tags: [id] }));
  for (const ordered of [rules, [...rules].reverse()]) {
    const { scan } = fixture(ordered), input = `api_key=${providerKey}`;
    const [finding] = scan(input, { sensitiveNames: ['api_key'] });
    assert.equal(finding.type, 'github-pat');
    assert.equal(finding.description, reference.metadata['github-pat'].description);
    assert.deepEqual(finding.tags, ['github-pat']);
    assert.equal(input.slice(finding.start, finding.end), providerKey);
  }
});

test('merged original and decoded findings use retained rule metadata and combined provenance', () => {
  const provider = { ...SecretShieldRules.rules.find(rule => rule.id === 'github-pat'), tags: ['provider', 'token'] };
  const { scan } = fixture([provider]);
  const encoded = Buffer.from(Buffer.from(providerKey).toString('hex')).toString('base64');
  const input = `dataset_key="${encoded}"`, [finding] = scan(input, { sensitiveNames: ['dataset_key'] });
  assert.equal(finding.type, provider.id);
  assert.equal(finding.description, provider.description);
  assert.deepEqual(finding.tags, ['provider', 'token', 'decoded:hex', 'decoded:base64', 'decode-depth:2']);
});

test('containing findings retain their own description and tags instead of nested rule labels', () => {
  const rules = [rule({ regex: '(BLOCK[\\s\\S]+END)', description: 'Containing block', tags: ['container'] }),
    rule({ id: 'fixture-nested', description: 'Nested', tags: ['nested'] })];
  const [finding] = fixture(rules).scan('BLOCK credential=ABC123 END');
  assert.equal(finding.type, 'fixture-metadata');
  assert.equal(finding.description, 'Containing block');
  assert.deepEqual(finding.tags, ['container']);
});

test('custom and client-ID findings include locations without invented Gitleaks labels', () => {
  for (const [input, policy, type] of [['dataset_key=short', { sensitiveNames: ['dataset_key'] }, 'custom-field'],
    ['client_id=short', {}, 'client-id']]) {
    assert.deepEqual(scan(input, policy), withLocations(input, [{ start: input.indexOf('short'), end: input.length, type }]));
  }
});

test('metadata is optional, bounded and preserves source order, duplicates and literal strings', () => {
  for (const metadata of [{}, { description: '', tags: [] }, { description: 'x'.repeat(2048), tags: Array(64).fill('t'.repeat(256)) },
    { description: '<service>', tags: ['日本語', 'api key', '日本語', 'decoded:hex', 'decode-depth:2'] }]) {
    const { scan } = fixture([rule(metadata)]), [finding] = scan('credential=ABC123');
    assert.equal(finding.description, metadata.description);
    assert.deepEqual(finding.tags, metadata.tags?.length ? metadata.tags : undefined);
  }
});

test('malformed bundled metadata fails initialization closed without caching partial rules', () => {
  const invalid = [null, false, 1, {}, [], 'x'.repeat(2049)].map(description => ({ description }));
  invalid.push(...[null, {}, 'tag', [null], [2], [''], ['t'.repeat(257)], Array(65).fill('tag')].map(tags => ({ tags })));
  for (const metadata of invalid) {
    const { api, source } = fixture([rule({ id: 'first-rule' }), rule(metadata)]);
    assert.throws(() => api.scan('credential=ABC123'), { message });
    source.rules[1] = rule({ description: 'Repaired', tags: ['service'] });
    assert.equal(api.scan('credential=ABC123').length, 1, 'failed initialization must be repairable');
  }
});

test('callers cannot mutate cached rule tags or tags in other findings and scans', () => {
  const configured = rule({ description: 'Service credential', tags: ['service', 'api'] });
  const { source, scan } = fixture([configured]), before = JSON.stringify(source);
  const first = scan('credential=ABC123\ncredential=DEF456');
  first[0].tags.push('caller-change');
  assert.deepEqual(first[1].tags, ['service', 'api']);
  assert.deepEqual(scan('credential=ABC123')[0].tags, ['service', 'api']);
  assert.equal(JSON.stringify(source), before);
  source.rules[0].tags.push('source-change');
  assert.deepEqual(scan('credential=ABC123')[0].tags, ['service', 'api']);
});

test('descriptions and tags do not change masking, counts, policies or expose secret text', () => {
  for (const mode of ['redact', 'block']) {
    const input = `api_key=${providerKey}`, result = redact(input, { mode });
    assert.equal(result.text, `api_key=${MASK}`);
    assert.equal(result.count, 1);
    assert.equal(result.findings[0].description, reference.metadata['github-pat'].description);
    assert.ok(!JSON.stringify(result.findings).includes(providerKey));
    assert.deepEqual(scan(result.text, { mode }), []);
  }
});
