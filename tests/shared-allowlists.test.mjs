import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import vm from 'node:vm';
import { MASK } from '../src/index.mjs';
import { providerKey } from './fixtures/gitleaks-credentials.mjs';

const core = await readFile(new URL('../src/core.js', import.meta.url), 'utf8');
const value = 'N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8', other = 'B9wK4s8H2yF7vN5rT6aZ';
const message = 'This text could not be scanned. Keep it local and shorten it before retrying.';
const exception = (targetRules, overrides = {}) => ({ condition: 'OR', regexTarget: 'secret',
  regexes: [`^(?:${value}|service:${value}|${providerKey})$`], stopwords: [], paths: [],
  ...(targetRules === undefined ? {} : { targetRules }), ...overrides });
function fixture(lists = [], change = () => {}) {
  const source = JSON.parse(JSON.stringify(SecretShieldRules));
  source.globalAllowlists.push(...lists);
  change(source);
  const context = vm.createContext({ SecretShieldRules: source });
  vm.runInContext(core, context);
  const api = context.SecretShieldCore;
  return { source, api, redact: (text, policy, options) => JSON.parse(JSON.stringify(api.redact(text, policy, text.length, options))) };
}

test('a targeted shared exception suppresses only its selected rule', () => {
  const { redact } = fixture([exception(['generic-api-key'])]);
  assert.equal(redact(`api_key=${value}`).count, 0);
  const input = `api_key=${providerKey}`, result = redact(input);
  assert.equal(result.count, 1);
  assert.equal(result.findings[0].type, 'github-pat');
  assert.equal(result.text, `api_key=${MASK}`);
  assert.equal(redact(`api_key=${other}`).text, `api_key=${MASK}`);
});

test('one shared exception can target multiple rules without becoming global', () => {
  const { redact } = fixture([exception(['generic-api-key', 'curl-auth-user'])]);
  const allowed = `api_key=${value}\ncurl -u service:${value} https://example.invalid`;
  assert.equal(redact(allowed).text, allowed);
  assert.equal(redact(`${allowed}\n${providerKey}`).text, `${allowed}\n${MASK}`);
});

test('omitted and empty target lists retain existing global exception behavior', () => {
  for (const targets of [undefined, []]) {
    const { redact } = fixture([exception(targets)]);
    const input = `api_key=${value}\n${providerKey}`;
    assert.equal(redact(input).text, input);
    assert.equal(redact(`api_key=${other}`).text, `api_key=${MASK}`);
  }
});

test('target rule IDs are exact and malformed or unknown references fail the whole scan', () => {
  for (const targets of [null, false, 4, {}, 'generic-api-key', [null], [1], [''], ['*'], ['__proto__'],
    ['unknown'], ['generic-api-key', 'unknown'], ['GENERIC-API-KEY'], [' generic-api-key'], ['freemius-secret-key']]) {
    const { api } = fixture([exception(targets)]);
    assert.throws(() => api.scan('ordinary prompt'), { message });
    assert.throws(() => api.redact(`api_key=${value}`), { message });
  }
});

test('nonempty targetRules on a per-rule allowlist are rejected instead of silently ignored', () => {
  const { api } = fixture([], source => {
    source.rules.find(rule => rule.id === 'generic-api-key').allowlists.push(exception(['github-pat']));
  });
  assert.throws(() => api.scan('ordinary prompt'), { message });
});

test('targeted criteria reuse secret, match and line targets with AND and OR conditions', () => {
  for (const condition of ['AND', 'OR']) for (const regexTarget of ['secret', 'match', 'line']) {
    const input = `api_key=${value} # synthetic-fixture`;
    const regex = regexTarget === 'secret' ? `^${value}$` : regexTarget === 'match' ? `api_key=${value}` : 'synthetic-fixture$';
    const { redact } = fixture([exception(['generic-api-key'], { condition, regexTarget,
      regexes: [regex], stopwords: [value.slice(0, 8).toUpperCase()] })]);
    assert.equal(redact(input).text, input, `${condition} ${regexTarget}`);
    assert.equal(redact(providerKey).text, MASK);
  }
  for (const condition of ['AND', 'OR']) {
    const { redact } = fixture([exception(['generic-api-key'], { condition, stopwords: ['never-matches'] })]);
    assert.equal(redact(`api_key=${value}`).count, condition === 'AND' ? 1 : 0);
  }
});

test('shared exceptions cannot disable explicit custom fields or supplemental client IDs', () => {
  const { redact } = fixture([exception(['generic-api-key'])]);
  for (const mode of ['redact', 'block']) {
    const input = `api_key=${value}\ndataset_key=${value}\nclient_id=${value}`;
    const result = redact(input, { mode, sensitiveNames: ['dataset_key'] });
    assert.equal(result.text, `api_key=${value}\ndataset_key=${MASK}\nclient_id=${MASK}`);
    assert.deepEqual(result.findings.map(item => item.type), ['custom-field', 'client-id']);
    const disabled = redact(input, { mode, protectClientIds: false, sensitiveNames: ['dataset_key'] });
    assert.equal(disabled.text, `api_key=${value}\ndataset_key=${MASK}\nclient_id=${value}`);
    assert.equal(redact(`api_key=${value}`, { mode, sensitiveNames: ['api_key'] }).text, `api_key=${MASK}`);
  }
});

test('global, per-rule and shared exclusions combine without leaking scopes', () => {
  const { redact } = fixture([exception(['generic-api-key']), exception(undefined, { regexes: [`^${other}$`] })], source => {
    source.rules.find(rule => rule.id === 'github-pat').allowlists.push(exception(undefined, { regexes: [`^${providerKey}$`] }));
  });
  const input = `api_key=${value}\napi_key=${other}\n${providerKey}`;
  assert.equal(redact(input).text, input);
  const next = fixture([exception(['generic-api-key'])]);
  assert.equal(next.redact(providerKey).text, MASK, 'another detector instance retains its own exclusions');
});

test('compilation leaves the original catalog untouched and duplicate target IDs remain equivalent', () => {
  const { source, redact } = fixture([exception(['generic-api-key', 'generic-api-key'])]);
  const before = JSON.stringify(source), bundled = JSON.stringify(SecretShieldRules);
  for (let i = 0; i < 10; i++) {
    assert.equal(redact(`api_key=${value}`).count, 0);
    assert.equal(redact(providerKey).count, 1);
  }
  assert.equal(JSON.stringify(source), before);
  assert.equal(JSON.stringify(SecretShieldRules), bundled);
  source.globalAllowlists.length = 0;
  assert.equal(redact(`api_key=${value}`).count, 0, 'the initialized detector owns its compiled configuration');
});

test('scoped exclusions also apply inside decoded text while retained findings keep tags and spans', () => {
  const codecs = [text => Buffer.from(text).toString('base64'), text => Buffer.from(text).toString('hex'),
    text => [...Buffer.from(text)].map(byte => '%' + byte.toString(16).padStart(2, '0')).join('')];
  const { redact } = fixture([exception(['generic-api-key'])]);
  for (const encode of codecs) {
    const allowed = encode(`api_key=${value}`), retained = encode(`api_key=${providerKey}`);
    assert.equal(redact(allowed).text, allowed);
    const result = redact(retained);
    assert.equal(result.text, MASK);
    assert.equal(result.findings[0].start, 0);
    assert.equal(result.findings[0].end, retained.length);
    assert.equal(result.findings[0].type, 'github-pat');
    assert.ok(result.findings[0].tags.includes('decode-depth:1'));
    assert.equal(redact(allowed, { sensitiveNames: ['api_key'] }).text, MASK);
  }
});

test('invalid shared criteria fail safely and a failed initialization does not poison a repaired catalog', () => {
  for (const fields of [{ regexes: [] }, { regexes: ['('] }, { regexes: 'bad' }, { stopwords: [1] },
    { paths: [1] }, { regexTarget: 'unknown' }, { condition: 'unknown' }]) {
    const { api } = fixture([exception(['generic-api-key'], fields)]);
    assert.throws(() => api.scan('ordinary prompt'), { message });
  }
  const { source, api, redact } = fixture([exception(['missing-rule'])]);
  assert.throws(() => api.scan('ordinary prompt'), { message });
  source.globalAllowlists.at(-1).targetRules = ['generic-api-key'];
  assert.equal(redact(`api_key=${value}`).count, 0);
  assert.equal(redact(providerKey).count, 1);
});

test('path criteria remain unsatisfied for prompts and cannot broaden an AND exclusion', () => {
  for (const condition of ['AND', 'OR']) {
    const { redact } = fixture([exception(['generic-api-key'], { condition, paths: ['.*'] })]);
    assert.equal(redact(`api_key=${value}`).count, condition === 'AND' ? 1 : 0);
    assert.equal(redact(providerKey).count, 1);
    const pathOnly = fixture([exception(['generic-api-key'], { condition, paths: ['.*'], regexes: [] })]);
    assert.equal(pathOnly.redact(`api_key=${value}`).count, 1);
  }
});

test('shared-allowlist behavior matches independently evaluated Gitleaks configurations', async () => {
  const reference = JSON.parse(await readFile(new URL('./fixtures/gitleaks-shared-allowlists.json', import.meta.url), 'utf8'));
  assert.ok(reference.cases.length >= 30);
  for (const item of reference.cases) {
    const { redact } = fixture(item.allowlists);
    const result = redact(item.input, { protectClientIds: false });
    assert.deepEqual(result.findings.map(finding => item.input.slice(finding.start, finding.end)), item.secrets, item.name);
    assert.deepEqual(result.findings.map(finding => finding.type).sort(), item.ruleIds, item.name);
  }
});

test('many findings with shared exclusions remain bounded and preserve other rules', () => {
  const script = `import assert from 'node:assert/strict'; import fs from 'node:fs'; import vm from 'node:vm';
    import './src/gitleaks-rules.js';
    const source=JSON.parse(JSON.stringify(SecretShieldRules));
    source.globalAllowlists.push(${JSON.stringify(exception(['generic-api-key']))});
    const context=vm.createContext({SecretShieldRules:source});
    vm.runInContext(fs.readFileSync('src/core.js','utf8'),context);
    const input=Array(10000).fill('api_key=${value}\\n${providerKey}').join('\\n');
    const result=context.SecretShieldCore.redact(input,undefined,input.length);
    assert.equal(result.count,10000);
    assert.ok(result.findings.every(item=>item.type==='github-pat'));`;
  execFileSync(process.execPath, ['--input-type=module', '-e', script],
    { cwd: new URL('..', import.meta.url), timeout: 10000, stdio: 'pipe' });
});
