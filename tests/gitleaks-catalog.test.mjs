import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import vm from 'node:vm';
import { scan, redact, MASK } from '../src/index.mjs';

const reference = JSON.parse(await readFile(new URL('./fixtures/gitleaks-catalog.json', import.meta.url), 'utf8'));
const core = await readFile(new URL('../src/core.js', import.meta.url), 'utf8');
const ids = Object.keys(reference.examples);

for (const id of ids) test(`${id} preserves pinned Gitleaks extraction, entropy and exclusions`, () => {
  const rule = SecretShieldRules.rules.find(item => item.id === id);
  const { maskGroup, reuseBoundary, ...raw } = rule;
  const context = vm.createContext({ SecretShieldRules: { ...SecretShieldRules, rules: [raw] } });
  vm.runInContext(core, context);
  for (const item of reference.cases.filter(item => item.ruleId === id)) {
    const findings = context.SecretShieldCore.scan(item.input);
    assert.deepEqual(Array.from(findings, finding => item.input.slice(finding.start, finding.end)), item.secrets, item.name);
    assert.ok(findings.every(finding => finding.type === id && finding.start >= 0 && finding.end <= item.input.length));
  }
});

test('the complete prompt catalog enables 217 rules and excludes the five filename-dependent rules', () => {
  assert.equal(SecretShieldRules.rules.length, 217);
  assert.equal(new Set(SecretShieldRules.rules.map(rule => rule.id)).size, 217);
  assert.equal(ids.length, 191);
  for (const id of ['freemius-secret-key', 'hashicorp-tf-password', 'kubernetes-secret-yaml', 'nuget-config-password', 'pkcs12-file']) {
    assert.ok(!SecretShieldRules.rules.some(rule => rule.id === id));
  }
  for (const id of ids) assert.ok(reference.examples[id], `${id} needs a positive upstream reference case`);
});

test('all newly enabled rule fixtures produce idempotent masking and exact UTF-16 spans', () => {
  for (const id of ids) {
    const rule = SecretShieldRules.rules.find(item => item.id === id);
    const context = vm.createContext({ SecretShieldRules: { ...SecretShieldRules, rules: [rule] } });
    vm.runInContext(core, context);
    for (const item of reference.cases.filter(item => item.ruleId === id)) {
      const result = context.SecretShieldCore.redact(item.input);
      const expectedValues = rule.maskGroup === 0 ? item.matches : item.browserSecrets ?? item.secrets;
      assert.deepEqual(Array.from(result.findings, finding => item.input.slice(finding.start, finding.end)), expectedValues, `${id}: ${item.name}`);
      let cursor = 0, expected = '';
      for (const finding of result.findings) {
        assert.ok(finding.start >= cursor && finding.end > finding.start);
        expected += item.input.slice(cursor, finding.start) + MASK;
        cursor = finding.end;
      }
      assert.equal(result.text, expected + item.input.slice(cursor), `${id}: ${item.name}`);
      assert.equal(context.SecretShieldCore.scan(result.text).length, 0, `${id}: ${item.name}`);
    }
  }
});

test('every new rule retains a positive finding in the combined catalog', () => {
  for (const id of ids) {
    const item = reference.cases.find(item => item.ruleId === id && item.secrets.length);
    assert.ok(item, id);
    const result = redact(item.input);
    for (const secret of item.secrets) {
      const start = item.input.indexOf(secret), end = start + secret.length;
      assert.ok(result.findings.some(finding => finding.start <= start && finding.end >= end), id);
    }
    assert.equal(scan(result.text).length, 0, id);
  }
});

test('mask capture configuration rejects invalid groups', () => {
  const original = SecretShieldRules.rules.find(rule => rule.id === 'jwt-base64');
  for (const maskGroup of [-1, 1.5, 100, '0']) {
    const context = vm.createContext({ SecretShieldRules: { ...SecretShieldRules, rules: [{ ...original, maskGroup }] } });
    vm.runInContext(core, context);
    assert.throws(() => context.SecretShieldCore.scan('ordinary text'), {
      message: 'This text could not be scanned. Keep it local and shorten it before retrying.',
    });
  }
});

test('Azure credentials reuse shared delimiters without losing repeated values', () => {
  const input = reference.examples['azure-ad-client-secret'];
  const value = redact(input).findings.map(finding => input.slice(finding.start, finding.end))[0];
  for (const delimiter of ['\n', ' ', ',', '"', "'"]) {
    const text = [value, value, value].join(delimiter);
    assert.equal(redact(text).text, [MASK, MASK, MASK].join(delimiter), delimiter);
    assert.equal(scan(text).length, 3, delimiter);
  }
});

test('invalid boundary enumeration data fails closed', () => {
  const rule = SecretShieldRules.rules.find(rule => rule.id === 'azure-ad-client-secret');
  for (const reuseBoundary of [null, 'true', 1, {}]) {
    const context = vm.createContext({ SecretShieldRules: { ...SecretShieldRules, rules: [{ ...rule, reuseBoundary }] } });
    vm.runInContext(core, context);
    assert.throws(() => context.SecretShieldCore.scan('ordinary text'), {
      message: 'This text could not be scanned. Keep it local and shorten it before retrying.',
    });
  }
});

test('all enabled rules finish on large ordinary and keyword-heavy drafts', () => {
  const inputs = ['Ordinary text without any credentials.\n'.repeat(2000),
    SecretShieldRules.rules.flatMap(rule => rule.keywords).join(' ') + '\n' + 'a '.repeat(40000)];
  for (const input of inputs) {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e',
      `import {scan} from './src/index.mjs'; scan(${JSON.stringify(input)});`],
    { cwd: new URL('../', import.meta.url), timeout: 10000, encoding: 'utf8' });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
  }
});
