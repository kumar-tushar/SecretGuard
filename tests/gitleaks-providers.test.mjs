import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { scan, redact, MASK } from '../src/index.mjs';

const reference = JSON.parse(await readFile(new URL('./fixtures/gitleaks-providers.json', import.meta.url), 'utf8'));
const core = await readFile(new URL('../src/core.js', import.meta.url), 'utf8');
const rules = Object.keys(reference.examples);
const collaboration = Object.keys(JSON.parse(await readFile(new URL('./fixtures/gitleaks-collaboration.json', import.meta.url), 'utf8')).examples).sort();
const catalog = Object.keys(JSON.parse(await readFile(new URL('./fixtures/gitleaks-catalog.json', import.meta.url), 'utf8')).examples);

test('the enabled catalog includes the requested provider families and structured credentials', () => {
  assert.deepEqual(SecretShieldRules.rules.map(rule => rule.id), ['generic-api-key', ...rules, 'private-key', 'jwt', 'curl-auth-header', 'curl-auth-user', ...collaboration, ...catalog]);
  assert.equal(rules.length, 10);
});

for (const id of rules) test(`${id} matches the independently generated Gitleaks reference`, () => {
  const context = vm.createContext({ SecretShieldRules: { ...SecretShieldRules, rules: SecretShieldRules.rules.filter(rule => rule.id === id) } });
  vm.runInContext(core, context);
  for (const fixture of reference.cases.filter(item => item.ruleId === id)) {
    const findings = context.SecretShieldCore.scan(fixture.input);
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
    assert.equal(context.SecretShieldCore.redact(fixture.input).text, expected, fixture.name);
    assert.equal(context.SecretShieldCore.scan(expected).length, 0, fixture.name);
  }
});

test('standalone provider values work without a keyword, field name or custom setting', () => {
  for (const [type, values] of Object.entries(reference.examples)) for (const value of values) {
    const text = `🔐 हिन्दी\n${value}\nKeep this sentence.`;
    for (const mode of ['redact', 'block']) {
      const start = text.indexOf(value);
      assert.deepEqual(scan(text, { mode, protectClientIds: false }), [{ start, end: start + value.length, type }]);
      assert.equal(redact(text).text, `🔐 हिन्दी\n${MASK}\nKeep this sentence.`);
    }
  }
});

test('provider findings take precedence over generic overlaps and mask the full occurrence once', () => {
  for (const [id, values] of Object.entries(reference.examples)) for (const value of values) {
    const text = `api_key="${value}"\n${value}\npassword=${value}`;
    const result = redact(text);
    assert.equal(result.count, 3, id);
    assert.equal(result.text, `api_key="${MASK}"\n${MASK}\npassword=${MASK}`, id);
    assert.ok(result.findings.every(item => item.type === id), id);
    assert.equal(scan(result.text).length, 0);
  }
  // GitHub's rule deliberately matches a fixed-length prefix of a longer value.
  // Merge its overlap with the generic finding so no suffix is duplicated/leaked.
  const value = reference.examples['github-pat'][0];
  assert.equal(redact(`api_key=${value}7R9v2M`).text, `api_key=${MASK}`);
  assert.equal(redact(`api_key=${value}7R9v2M`).count, 1);
});

test('mixed-provider drafts preserve order, duplicates, surrounding punctuation and idempotence', () => {
  const values = Object.values(reference.examples).flat();
  const text = values.map(value => `  "${value}";`).join('\r\n');
  const findings = scan(text);
  assert.equal(findings.length, values.length);
  assert.deepEqual(findings.map(item => text.slice(item.start, item.end)), values);
  assert.equal(redact(text).text, values.map(() => `  "${MASK}";`).join('\r\n'));
  assert.equal(scan(redact(text).text).length, 0);
  for (let i = 0; i < 10; i++) assert.deepEqual(scan(text), findings);
});

test('malformed whole-match rule data fails closed rather than hanging', () => {
  for (const regex of ['', '^', '(?:)']) {
    const context = vm.createContext({ SecretShieldRules: { globalAllowlists: [], rules: [
      { id: 'invalid', regex, secretGroup: 0, entropy: 0, keywords: [], allowlists: [] },
    ] } });
    vm.runInContext(core, context);
    assert.throws(() => context.SecretShieldCore.scan('ordinary text'), {
      message: 'This text could not be scanned. Keep it local and shorten it before retrying.',
    });
  }
});
