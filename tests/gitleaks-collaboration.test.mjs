import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { scan, redact, MASK } from '../src/index.mjs';

const reference = JSON.parse(await readFile(new URL('./fixtures/gitleaks-collaboration.json', import.meta.url), 'utf8'));
const core = await readFile(new URL('../src/core.js', import.meta.url), 'utf8');

for (const id of Object.keys(reference.examples)) test(`${id} matches the independently evaluated Gitleaks reference`, () => {
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

test('Slack, Stripe and npm examples are detected without labels and masked completely', () => {
  for (const [id, values] of Object.entries(reference.examples)) for (const value of values) {
    for (const mode of ['redact', 'block']) {
      const text = `🛡️ हिन्दी\n${value}\nKeep this.`;
      const result = redact(text, { mode });
      assert.equal(result.count, 1, id);
      assert.deepEqual(result.findings.map(item => text.slice(item.start, item.end)), [value], id);
      assert.equal(result.text, `🛡️ हिन्दी\n${MASK}\nKeep this.`, id);
      assert.equal(scan(result.text).length, 0, id);
    }
  }
});

test('overlapping Slack families and generic assignments mask a complete occurrence once', () => {
  for (const values of Object.values(reference.examples)) for (const value of values) {
    const text = `api_key="${value}"\n${value}\npassword=${value}`;
    const result = redact(text);
    assert.equal(result.count, 3, value);
    assert.equal(result.text, `api_key="${MASK}"\n${MASK}\npassword=${MASK}`, value);
    assert.equal(scan(result.text).length, 0);
  }
});

test('mixed formats retain repeated occurrences and order across deterministic scans', () => {
  const values = Object.values(reference.examples).flat();
  const text = values.map(value => `"${value}";`).join('\r\n');
  const expected = values.map(() => `"${MASK}";`).join('\r\n');
  for (let i = 0; i < 10; i++) {
    const result = redact(text);
    assert.deepEqual(result.findings.map(item => text.slice(item.start, item.end)), values);
    assert.equal(result.text, expected);
    assert.equal(scan(result.text).length, 0);
  }
});
