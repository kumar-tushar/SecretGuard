import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import vm from 'node:vm';
import { MASK } from '../src/index.mjs';
import { providerKey } from './fixtures/gitleaks-credentials.mjs';

const core = await readFile(new URL('../src/core.js', import.meta.url), 'utf8');
const message = 'This text could not be scanned. Keep it local and shorten it before retrying.';
const rule = (id, regex, extra = {}) => ({ id, regex, secretGroup: 1, entropy: 0, keywords: [], allowlists: [], ...extra });
const primary = extra => rule('fixture-primary', 'credential=([A-Z][A-Z0-9]{5,})', { required: [{ id: 'fixture-context' }], ...extra });
const contextRule = extra => rule('fixture-context', '(SERVICE)', { skipReport: true, ...extra });
function fixture(rules = [primary(), contextRule()], lists = [], change = () => {}) {
  const source = JSON.parse(JSON.stringify(SecretShieldRules));
  source.rules.push(...rules);
  source.globalAllowlists.push(...lists);
  change(source);
  const context = vm.createContext({ SecretShieldRules: source });
  vm.runInContext(core, context);
  const api = context.SecretShieldCore;
  return { api, source, scan: (text, policy, options) => JSON.parse(JSON.stringify(api.scan(text, policy, text.length, options))),
    redact: (text, policy, options) => JSON.parse(JSON.stringify(api.redact(text, policy, text.length, options))) };
}

test('a composite reports each primary only when all named supporting rules match', () => {
  const { redact } = fixture([primary({ required: [{ id: 'fixture-context' }, { id: 'fixture-region' }] }), contextRule(),
    rule('fixture-region', '(REGION)', { skipReport: true })]);
  for (const text of ['credential=ABC123', 'SERVICE credential=ABC123', 'REGION credential=ABC123']) assert.equal(redact(text).count, 0);
  const text = 'REGION\ncredential=ABC123\nSERVICE\ncredential=DEF456';
  const result = redact(text);
  assert.deepEqual(result.findings.map(item => text.slice(item.start, item.end)), ['ABC123', 'DEF456']);
  assert.equal(result.text, `REGION\ncredential=${MASK}\nSERVICE\ncredential=${MASK}`);
});

test('line proximity is inclusive, bidirectional and evaluated per occurrence', () => {
  const { redact } = fixture([primary({ required: [{ id: 'fixture-context', withinLines: 1 }] }), contextRule()]);
  for (const text of ['SERVICE\ncredential=ABC123', 'credential=ABC123\nSERVICE', 'SERVICE credential=ABC123']) assert.equal(redact(text).count, 1);
  for (const text of ['SERVICE\n\ncredential=ABC123', 'credential=ABC123\n\nSERVICE']) assert.equal(redact(text).count, 0);
  const text = 'credential=ABC123\nSERVICE\n\ncredential=DEF456';
  assert.deepEqual(redact(text).findings.map(item => text.slice(item.start, item.end)), ['ABC123']);
  const sameLine = fixture([primary({ required: [{ id: 'fixture-context', withinLines: 0 }] }), contextRule()]);
  assert.equal(sameLine.redact('SERVICE credential=ABC123').count, 1);
  assert.equal(sameLine.redact('SERVICE\ncredential=ABC123').count, 0);
});

test('column proximity uses full-match starts rather than the captured secret', () => {
  for (const [distance, expected] of [[7, 0], [8, 1]]) {
    const { redact } = fixture([primary({ required: [{ id: 'fixture-context', withinColumns: distance }] }), contextRule()]);
    assert.equal(redact('SERVICE credential=ABC123').count, expected);
  }
  const { redact } = fixture([primary({ required: [{ id: 'fixture-context', withinColumns: 0 }] }), contextRule()]);
  assert.equal(redact('prefix\nSERVICE\ncredential=ABC123').count, 1, 'column-only constraints do not require nearby lines');
});

test('combined constraints require a single supporting match inside both bounds', () => {
  const { redact } = fixture([primary({ required: [{ id: 'fixture-context', withinLines: 0, withinColumns: 2 }] }), contextRule()]);
  assert.equal(redact('credential=ABC123 SERVICE\nSERVICE').count, 0, 'different supports cannot satisfy the two dimensions separately');
  const nearby = fixture([primary({ required: [{ id: 'fixture-context', withinLines: 1, withinColumns: 1 }] }), contextRule()]);
  assert.equal(nearby.redact('prefix\n SERVICE\ncredential=ABC123').count, 1);
  assert.equal(nearby.redact('prefix\n  SERVICE\ncredential=ABC123').count, 0);
});

test('UTF-8 byte columns, LF, CRLF and newline-start matches follow upstream coordinates', () => {
  const input = 'SERVICE 😀credential=ABC123';
  for (const [limit, expected] of [[11, 0], [12, 1]]) {
    const { redact } = fixture([primary({ required: [{ id: 'fixture-context', withinColumns: limit }] }), contextRule()]);
    assert.equal(redact(input).count, expected);
  }
  const { redact } = fixture([primary({ required: [{ id: 'fixture-context', withinLines: 1 }] }), contextRule()]);
  assert.equal(redact('SERVICE\r\ncredential=ABC123').count, 1);
  assert.equal(redact('SERVICE\r\n\r\ncredential=ABC123').count, 0);
  const newline = fixture([primary({ regex: '\\ncredential=([A-Z0-9]+)', required: [{ id: 'fixture-context', withinLines: 0 }] }), contextRule()]);
  assert.equal(newline.redact('prefix\ncredential=ABC123 SERVICE').count, 1);
});

test('skipReport suppresses standalone support while public supporting rules still report', () => {
  const hidden = fixture();
  assert.deepEqual(hidden.scan('SERVICE'), []);
  assert.equal(hidden.redact('SERVICE credential=ABC123').text, `SERVICE credential=${MASK}`);
  const visible = fixture([primary(), contextRule({ skipReport: false })]);
  const text = 'SERVICE credential=ABC123';
  assert.deepEqual(visible.scan(text).map(item => item.type), ['fixture-context', 'fixture-primary']);
  assert.equal(visible.redact(text).text, `${MASK} credential=${MASK}`);
  assert.deepEqual(fixture([contextRule()]).scan('SERVICE'), []);
});

test('supporting rules use raw accepted matches, bypassing their own dependencies and keyword prefilter', () => {
  const { redact } = fixture([primary(), contextRule({ keywords: ['absent-prefilter'], required: [{ id: 'fixture-region' }] }),
    rule('fixture-region', '(REGION)', { skipReport: true })]);
  assert.equal(redact('SERVICE credential=ABC123').count, 1);
  const cyclic = fixture([primary(), contextRule({ required: [{ id: 'fixture-primary' }] })]);
  assert.equal(cyclic.redact('SERVICE credential=ABC123').count, 1);
  const self = fixture([primary({ required: [{ id: 'fixture-primary', withinLines: 0, withinColumns: 0 }] })]);
  assert.equal(self.redact('credential=ABC123').count, 1);
});

test('primary keyword prefilters still apply and duplicate required IDs provide alternative bounds', () => {
  const disabled = fixture([primary({ keywords: ['must-appear'] }), contextRule()]);
  assert.equal(disabled.redact('SERVICE credential=ABC123').count, 0);
  assert.equal(disabled.redact('must-appear SERVICE credential=ABC123').count, 1);
  const { redact } = fixture([primary({ required: [{ id: 'fixture-context', withinLines: 0 }, { id: 'fixture-context', withinLines: 2 }] }), contextRule()]);
  assert.equal(redact('SERVICE\n\ncredential=ABC123').count, 1);
});

test('global, rule-specific and shared exclusions on supports are applied before dependencies', () => {
  const list = { regexes: ['^SERVICE$'], stopwords: [], paths: [] };
  for (const kind of ['global', 'shared', 'rule']) {
    const { redact } = fixture([primary(), contextRule(kind === 'rule' ? { allowlists: [list] } : {})],
      kind === 'global' ? [list] : kind === 'shared' ? [{ ...list, targetRules: ['fixture-context'] }] : []);
    assert.equal(redact('SERVICE credential=ABC123').count, 0, kind);
  }
  const excludedPrimary = fixture([primary({ allowlists: [{ ...list, regexes: ['^ABC123$'] }] }), contextRule()]);
  assert.equal(excludedPrimary.redact('SERVICE credential=ABC123').count, 0);
});

test('entropy and captures still govern auxiliary candidates', () => {
  const context = contextRule({ regex: 'service=(A+)', entropy: 1 });
  assert.equal(fixture([primary(), context]).redact('service=AAAAAA credential=ABC123').count, 0);
  const captured = fixture([primary(), contextRule({ regex: 'service=(SERVICE)' })]);
  assert.equal(captured.redact('service=SERVICE credential=ABC123').count, 1);
});

test('custom fields, client IDs and independent rules cannot be disabled by an unmet dependency', () => {
  const { redact } = fixture();
  const text = `credential=ABC123\ndataset_key=short\nclient_id=public-client\n${providerKey}`;
  const result = redact(text, { sensitiveNames: ['dataset_key'] });
  assert.equal(result.text, `credential=ABC123\ndataset_key=${MASK}\nclient_id=${MASK}\n${MASK}`);
  assert.deepEqual(result.findings.map(item => item.type), ['custom-field', 'client-id', 'github-pat']);
});

test('invalid required metadata or unknown references fail the complete scan without caching partial state', () => {
  for (const required of [null, {}, 'context', [null], [1], [{}], [{ id: '' }], [{ id: 'missing' }],
    [{ id: 'fixture-context', withinLines: -1 }], [{ id: 'fixture-context', withinLines: 1.5 }],
    [{ id: 'fixture-context', withinColumns: null }], [{ id: 'fixture-context', withinColumns: '1' }],
    [{ id: 'fixture-context', withinColumns: Number.MAX_SAFE_INTEGER + 1 }]]) {
    const { api } = fixture([primary({ required }), contextRule()]);
    assert.throws(() => api.scan('ordinary prompt'), { message });
  }
  for (const skipReport of [null, 1, 'true', {}]) {
    const { api } = fixture([primary({ skipReport }), contextRule()]);
    assert.throws(() => api.scan('ordinary prompt'), { message });
  }
  const { api, source, redact } = fixture([primary({ required: [{ id: 'missing' }] }), contextRule()]);
  assert.throws(() => api.scan('ordinary prompt'), { message });
  source.rules.find(item => item.id === 'fixture-primary').required[0].id = 'fixture-context';
  assert.equal(redact('SERVICE credential=ABC123').count, 1);
});

test('decoded composite findings retain original spans and encoding provenance', () => {
  const encoders = [text => Buffer.from(text).toString('base64'), text => Buffer.from(text).toString('hex'),
    text => [...Buffer.from(text)].map(byte => '%' + byte.toString(16).padStart(2, '0')).join('')];
  const { redact } = fixture([primary({ required: [{ id: 'fixture-context', withinLines: 0, withinColumns: 0 }] }), contextRule()]);
  for (const encode of encoders) {
    const encoded = encode('SERVICE\ncredential=ABC123'), text = `😀 ${encoded}\nKeep.`;
    const result = redact(text);
    assert.equal(result.text, `😀 ${MASK}\nKeep.`);
    assert.deepEqual(result.findings.map(item => text.slice(item.start, item.end)), [encoded]);
    assert.ok(result.findings[0].tags.includes('decode-depth:1'));
  }
  const absent = Buffer.from('credential=ABC123').toString('base64');
  assert.equal(redact(absent).count, 0);
});

test('proximity follows original encoded match starts rather than decoded secret columns', () => {
  const encoded = Buffer.from('SERVICE credential=ABC123').toString('hex');
  const { redact } = fixture([primary({ required: [{ id: 'fixture-context', withinColumns: 0 }] }), contextRule()]);
  assert.equal(redact(encoded).text, MASK);
  assert.equal(redact('SERVICE credential=ABC123').count, 0);
  const context = Buffer.from('SERVICE context phrase').toString('base64');
  assert.equal(fixture().redact(`${context}\ncredential=ABC123`).count, 1, 'decoded context can enable an unchanged primary in the browser scanner');
});

test('composite scanning preserves catalog data and returns only existing public finding fields', () => {
  const { source, redact } = fixture(), before = JSON.stringify(SecretShieldRules);
  const configured = JSON.stringify(source), result = redact('SERVICE credential=ABC123');
  assert.deepEqual(Object.keys(result.findings[0]).sort(), ['end', 'endColumn', 'endLine', 'start', 'startColumn', 'startLine', 'type']);
  assert.equal(JSON.stringify(result.findings).includes('ABC123'), false);
  assert.equal(JSON.stringify(source), configured);
  assert.equal(JSON.stringify(SecretShieldRules), before);
});

test('composite results match independently evaluated Gitleaks reference configurations', async () => {
  const reference = JSON.parse(await readFile(new URL('./fixtures/gitleaks-composite.json', import.meta.url), 'utf8'));
  assert.ok(reference.cases.length >= 50);
  for (const item of reference.cases) {
    const { redact } = fixture(item.rules, item.allowlists);
    const result = redact(item.input, { protectClientIds: false });
    assert.deepEqual(result.findings.map(finding => item.input.slice(finding.start, finding.end)), item.secrets, item.name);
    assert.deepEqual(result.findings.map(finding => finding.type).sort(), item.ruleIds, item.name);
  }
});

test('large dependency sets stay bounded and exhaustive comparison exhaustion fails closed', () => {
  const script = `import fs from 'node:fs'; import vm from 'node:vm'; import assert from 'node:assert/strict';
    import './src/gitleaks-rules.js';
    const primary=${JSON.stringify(primary({ required: [{ id: 'fixture-context', withinLines: 0, withinColumns: 0 }] }))};
    const contextRule=${JSON.stringify(contextRule())};
    const source=JSON.parse(JSON.stringify(SecretShieldRules));source.rules.push(primary,contextRule);
    const context=vm.createContext({SecretShieldRules:source});vm.runInContext(fs.readFileSync('src/core.js','utf8'),context);
    const api=context.SecretShieldCore;
    const many=Array(10000).fill('SERVICE credential=ABC123').join('\\n');
    assert.equal(api.redact(many,undefined,many.length).count,0);
    const good=Array(10000).fill('SERVICE\\ncredential=ABC123').join('\\n');
    primary.required[0].withinLines=1;
    const fresh=vm.createContext({SecretShieldRules:source});vm.runInContext(fs.readFileSync('src/core.js','utf8'),fresh);
    assert.equal(fresh.SecretShieldCore.redact(good,undefined,good.length).count,10000);
    const expensive=JSON.parse(JSON.stringify(source));
    expensive.rules.find(rule=>rule.id==='fixture-primary').required=Array(101).fill({id:'fixture-context'});
    const limited=vm.createContext({SecretShieldRules:expensive});vm.runInContext(fs.readFileSync('src/core.js','utf8'),limited);
    assert.throws(()=>limited.SecretShieldCore.redact(good,undefined,good.length),{message:${JSON.stringify(message)}});`;
  execFileSync(process.execPath, ['--input-type=module', '-e', script],
    { cwd: new URL('..', import.meta.url), timeout: 10000, stdio: 'pipe' });
});
