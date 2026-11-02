import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import vm from 'node:vm';
import { scan, redact, MASK, ScanError } from '../src/index.mjs';
import { providerKey } from './fixtures/gitleaks-credentials.mjs';
import { withLocations } from './fixtures/finding-locations.mjs';

const core = await readFile(new URL('../src/core.js', import.meta.url), 'utf8');
const keys = ['startLine', 'startColumn', 'endLine', 'endColumn'];
const coordinates = finding => Object.fromEntries(keys.map(key => [key, finding[key]]));
const codecs = {
  base64: text => Buffer.from(text).toString('base64'), hex: text => Buffer.from(text).toString('hex'),
  percent: text => [...Buffer.from(text)].map(byte => '%' + byte.toString(16).padStart(2, '0')).join(''),
};
function checked(input, policy, api = { scan, redact }) {
  const result = api.scan(input, policy, input.length);
  assert.ok(result.length);
  assert.deepEqual(JSON.parse(JSON.stringify(result)), withLocations(input, JSON.parse(JSON.stringify(result))));
  const masked = api.redact(input, policy, input.length);
  assert.equal(masked.count, result.length);
  assert.equal(api.scan(masked.text, policy, masked.text.length).length, 0);
  return result;
}

test('locations describe selected secret spans rather than assignment labels or redacted text', () => {
  const input = `Title\n\n😀 api_key=${providerKey}\nclient_id=short`;
  const result = checked(input);
  assert.deepEqual(result.map(coordinates), [
    { startLine: 3, startColumn: 14, endLine: 3, endColumn: 13 + providerKey.length },
    { startLine: 4, startColumn: 11, endLine: 4, endColumn: 15 },
  ]);
  assert.equal(redact(input).text, `Title\n\n😀 api_key=${MASK}\nclient_id=${MASK}`);
});

test('custom and client-ID locations use UTF-8 bytes with inclusive ends for Unicode and lone surrogates', () => {
  for (const value of ['a', 'é', '中', '😀', 'e\u0301', '\ud800', '\udfff']) {
    for (const mode of ['redact', 'block']) {
      const input = `é\tclient_id="${value}"\ndataset_key="${value}"`;
      checked(input, { mode, sensitiveNames: ['dataset_key'] });
    }
  }
});

test('LF, CRLF, bare CR, tabs and final lines preserve original prompt coordinates', () => {
  for (const separator of ['\n', '\r\n', '\r']) for (const tail of ['', '\n']) {
    const input = `Header${separator}client_id="first${separator}🧪last"${tail}`;
    const [finding] = checked(input);
    assert.equal(finding.startLine, separator.includes('\n') ? 2 : 1);
    assert.equal(finding.endLine, separator.includes('\n') ? 3 : 1);
  }
  const [finding] = checked('client_id="\nvalue\n"');
  assert.deepEqual(coordinates(finding), { startLine: 1, startColumn: 12, endLine: 2, endColumn: 6 });
});

test('merged provider/custom findings report the complete retained masking span', () => {
  const input = `😀\nproject_secret="prefix ${providerKey}\nend"\n${providerKey}`;
  const result = checked(input, { sensitiveNames: ['project_secret'] });
  assert.equal(result[0].type, 'github-pat');
  assert.equal(result[0].startLine, 2);
  assert.equal(result[0].startColumn, 17);
  assert.equal(result[0].endLine, 3);
  assert.equal(result[0].endColumn, 3);
  assert.equal(result[1].startLine, 4);
  assert.equal(result[1].startColumn, 1);
});

test('nested codecs report locations of original encoded blobs rather than decoded lines', () => {
  for (const route of [['hex'], ['base64'], ['percent'], ['hex', 'base64'], ['base64', 'percent'],
    ['percent', 'hex'], ['hex', 'percent', 'base64'], ['base64', 'hex', 'percent'], ['hex', 'hex', 'hex']]) {
    const encoded = route.reduce((text, codec) => codecs[codec](text), `client_id="first\nlast"`);
    const input = `😀\n  ${encoded}\nKeep.`;
    const [finding] = checked(input);
    assert.deepEqual(coordinates(finding), { startLine: 2, startColumn: 3, endLine: 2, endColumn: 2 + encoded.length });
    assert.equal(input.slice(finding.start, finding.end), encoded);
  }
});

test('coarse percent and cross-segment cURL mappings retain original merged locations', () => {
  const percent = `%67${providerKey.slice(1)}; harmless=%20`;
  const [finding] = checked(`😀\n${percent}\nKeep.`);
  assert.equal(finding.endColumn, percent.length);
  const user = codecs.hex('service-username-1'), password = codecs.base64('N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8');
  checked(`é\ncurl -u "${user}:${password}" https://example.invalid`);
});

test('encoded field labels do not move unchanged plaintext value locations', () => {
  const input = `Header\n${codecs.base64('project_secret')}: "short value"`;
  const [finding] = checked(input, { sensitiveNames: ['project_secret'] });
  assert.equal(input.slice(finding.start, finding.end), 'short value');
  assert.equal(finding.tags, undefined);
  assert.equal(finding.startLine, 2);
});

test('all enabled catalog examples and encoded reference fixtures have independently checked coordinates', async () => {
  const metadata = JSON.parse(await readFile(new URL('./fixtures/gitleaks-metadata.json', import.meta.url), 'utf8'));
  for (const [id, item] of Object.entries(metadata.metadata)) {
    const rule = SecretShieldRules.rules.find(rule => rule.id === id);
    const context = vm.createContext({ SecretShieldRules: { ...SecretShieldRules, rules: [rule] } });
    vm.runInContext(core, context);
    const input = '🛡️\n' + item.input + '\nKeep.';
    checked(input, { protectClientIds: false }, context.SecretShieldCore);
  }
  for (const codec of Object.keys(codecs)) {
    const reference = JSON.parse(await readFile(new URL(`./fixtures/gitleaks-${codec}.json`, import.meta.url), 'utf8'));
    for (const item of reference.cases) checked('é\n' + item.input + '\nKeep.');
  }
});

test('locations are independent numeric metadata and do not retain secret text or previous calls', () => {
  const input = 'client_id=secret', first = checked(input);
  first[0].startLine = 999;
  assert.equal(scan(input)[0].startLine, 1);
  for (const key of keys) assert.equal(typeof scan(input)[0][key], 'number');
  assert.ok(!JSON.stringify(scan(input)).includes('secret'));
  assert.deepEqual(scan('ordinary text'), []);
});

test('144 official whole-capture reference cases retain documented original-location adaptations', async () => {
  const reference = JSON.parse(await readFile(new URL('./fixtures/gitleaks-locations.json', import.meta.url), 'utf8'));
  assert.equal(reference.cases.length, 144);
  const context = vm.createContext({ SecretShieldRules: { rules: [reference.rule], globalAllowlists: [] } });
  vm.runInContext(core, context);
  let differences = 0;
  for (const item of reference.cases) {
    const [finding] = checked(item.input, { protectClientIds: false }, context.SecretShieldCore);
    assert.equal(item.input.slice(finding.start, finding.end), item.secret);
    assert.deepEqual(coordinates(finding), item.location, item.name);
    if (!item.input.includes('\n')) assert.deepEqual(coordinates(finding), item.upstreamLocation, item.name);
    if (JSON.stringify(item.location) !== JSON.stringify(item.upstreamLocation)) differences++;
  }
  assert.equal(differences, 102, 'Normalized LF origins and unterminated multiline ends are explicit browser adaptations');
});

test('coordinate mapping rejects invalid ordering and spans that split a Unicode surrogate pair', () => {
  const { findingLocations } = globalThis.SecretShieldCore;
  for (const findings of [[{ start: -1, end: 2 }], [{ start: 0, end: 0 }], [{ start: 0, end: 3 }],
    [{ start: 0, end: 1 }], [{ start: 1, end: 2 }], [{ start: 0.5, end: 2 }],
    [{ start: 0, end: 2 }, { start: 0, end: 2 }]]) assert.throws(() => findingLocations('😀', findings), ScanError);
});

test('many findings across long prompts map in one forward pass', () => {
  const script = `import assert from 'node:assert/strict'; import {scan} from './src/index.mjs';
    const text='Header\\n'+('😀 client_id=short\\n').repeat(20000);
    const result=scan(text,undefined,text.length);
    assert.equal(result.length,20000);
    assert.equal(result[0].startLine,2);assert.equal(result.at(-1).startLine,20001);
    for(const item of result){assert.equal(item.startColumn,16);assert.equal(item.endColumn,20);}`;
  execFileSync(process.execPath, ['--input-type=module', '-e', script], { cwd: new URL('..', import.meta.url), timeout: 5000, stdio: 'pipe' });
});
