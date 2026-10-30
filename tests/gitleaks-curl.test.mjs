import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import vm from 'node:vm';
import { scan, redact, MASK } from '../src/index.mjs';

const reference = JSON.parse(await readFile(new URL('./fixtures/gitleaks-curl.json', import.meta.url), 'utf8'));
const core = await readFile(new URL('../src/core.js', import.meta.url), 'utf8');
const examples = reference.cases.filter(item => item.name.startsWith('example '));

for (const id of Object.keys(reference.examples)) test(`${id} matches the independently evaluated Gitleaks reference`, () => {
  // Compare the complete expression without browser enumeration. CR-heavy
  // cases use the normalized prefix below; the raw JavaScript port can hang.
  const rules = SecretShieldRules.rules.filter(rule => rule.id === id).map(({ command, ...rule }) => rule);
  const context = vm.createContext({ SecretShieldRules: { ...SecretShieldRules, rules } });
  vm.runInContext(core, context);
  for (const fixture of reference.cases.filter(item => item.ruleId === id && !item.prefixStress)) {
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
  }
});

for (const id of Object.keys(reference.examples)) test(`${id} enumerates every accepted option for idempotent browser masking`, () => {
  const context = vm.createContext({ SecretShieldRules: { ...SecretShieldRules, rules: SecretShieldRules.rules.filter(rule => rule.id === id) } });
  vm.runInContext(core, context);
  for (const fixture of reference.cases.filter(item => item.ruleId === id)) {
    const result = context.SecretShieldCore.redact(fixture.input);
    const expected = fixture.optionSecrets ?? fixture.secrets;
    assert.deepEqual(Array.from(result.findings, item => fixture.input.slice(item.start, item.end)), expected, fixture.name);
    assert.equal(context.SecretShieldCore.scan(result.text).length, 0, fixture.name);
  }
});

test('cURL automatic extraction selects every populated alternative without including command text', () => {
  for (const fixture of examples) for (const mode of ['redact', 'block']) {
    const text = '🛡️ हिन्दी\n' + fixture.input + '\nKeep this sentence.';
    const result = redact(text, { mode });
    assert.deepEqual(result.findings.map(item => text.slice(item.start, item.end)), fixture.secrets);
    assert.equal(result.text, fixture.secrets.reduce((output, secret) => output.replace(secret, MASK), text));
    assert.equal(scan(result.text).length, 0);
  }
  const header = examples[0], secret = header.secrets[0];
  const text = secret + '\n' + header.input;
  const start = text.lastIndexOf(secret);
  assert.deepEqual(scan(text), [{ start, end: start + secret.length, type: header.ruleId }]);
  assert.equal(redact(text).text, secret + '\n' + header.input.replace(secret, MASK));
});

test('automatic groups preserve first populated capture semantics and whole-match fallback', () => {
  for (const [regex, input, expected] of [
    ['prefix:(a(bc))', 'prefix:abc', 'abc'],
    ['(a+)|(b+)', 'bbb', 'bbb'],
    ['(a*)word', 'word', 'word'],
    ['plain', 'plain', 'plain'],
  ]) {
    const context = vm.createContext({ SecretShieldRules: { globalAllowlists: [], rules: [
      { id: 'fixture', regex, secretGroup: 0, entropy: 0, keywords: [], allowlists: [] },
    ] } });
    vm.runInContext(core, context);
    const findings = context.SecretShieldCore.scan(input);
    assert.equal(findings.length, 1);
    assert.equal(input.slice(findings[0].start, findings[0].end), expected);
  }
});

test('invalid command enumeration data fails closed', () => {
  const original = SecretShieldRules.rules.find(rule => rule.id === 'curl-auth-header');
  for (const command of [null, {}, { start: '(', prefix: original.command.prefix },
    { start: original.command.start, prefix: 'different prefix' },
    { start: original.command.start, prefix: original.regex },
    { ...original.command, lineBreakGroups: -1 }, { ...original.command, lineBreakGroups: 1.5 }]) {
    const context = vm.createContext({ SecretShieldRules: { globalAllowlists: [], rules: [{ ...original, command }] } });
    vm.runInContext(core, context);
    assert.throws(() => context.SecretShieldCore.scan(examples[0].input), {
      message: 'This text could not be scanned. Keep it local and shorten it before retrying.',
    });
  }
});

test('cURL and generic/provider overlaps are reviewed and masked only once', () => {
  const token = 'ghp_N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8B9wK';
  const headers = ['Authorization: Bearer ', 'X-Api-Key: '];
  for (const header of headers) {
    const text = `curl -H "${header}${token}" https://api.example.com`;
    const result = redact(text);
    assert.equal(result.count, 1);
    assert.equal(result.text, `curl -H "${header}${MASK}" https://api.example.com`);
    assert.equal(scan(result.text).length, 0);
  }
  const text = `curl -u "service-user:${token}" https://api.example.com`;
  const result = redact(text);
  assert.equal(result.count, 1);
  assert.equal(result.text, `curl -u ${MASK} https://api.example.com`);
});

test('cURL scope and exclusions do not restore retired context detection', () => {
  for (const text of ['curl -u "<username>:<password>"', 'curl -u service-user:password',
    'curl --user "service-user:[hidden]"', 'curl -u "${USER}:${PASSWORD}"',
    'curl -H "Authorization: Bearer xxxxxxxxxx"', 'curl -H "Content-Type: application/json"',
    'api_key\n\nhju867fggfgxxjgswrxl', 'key={event.id}', 'Explain curl authentication.']) {
    assert.deepEqual(scan(text), [], text);
  }
});

test('repeated commands preserve offsets, order and the complete masked result', () => {
  const commands = examples.map(item => item.input), secrets = examples.flatMap(item => item.secrets);
  // Preserve the upstream expression's command/line scope when composing examples.
  const text = commands.join('\n'.repeat(10));
  const expected = examples.map(item => item.secrets.reduce((output, secret) => output.replace(secret, MASK), item.input)).join('\n'.repeat(10));
  for (let i = 0; i < 10; i++) {
    const result = redact(text);
    assert.deepEqual(result.findings.map(item => text.slice(item.start, item.end)), secrets);
    assert.equal(result.text, expected);
    assert.equal(scan(result.text).length, 0);
  }
});

test('long cURL near matches and repeated keywords finish without blocking the scanner', () => {
  const inputs = [['curl ' + 'a'.repeat(99000), 0], ['curl\n' + 'ordinary line\n'.repeat(5000), 0],
    ['curl ' + '-H '.repeat(20000), 0], ['curl '.repeat(19000), 0],
    ['curl '.repeat(18000) + '-H "Authorization: Bearer too-short"', 0],
    ['curl '.repeat(18000) + '-u "service-user:password"', 0],
    ['curl' + '\r'.repeat(95000) + '\n'.repeat(7) + '-H "Authorization: Bearer N7q2V9m4R8s6T3x5"', 1],
    ['curl ' + ('\r'.repeat(10000) + '\n').repeat(8) + '-u service-user:N7q2V9m4R8s6T3x5', 0]];
  for (const [input, count] of inputs) {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e',
      `import { scan } from './src/index.mjs'; if (scan(${JSON.stringify(input)}).length !== ${count}) process.exit(1);`],
    { cwd: new URL('../', import.meta.url), timeout: 3000, encoding: 'utf8' });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
  }
});
