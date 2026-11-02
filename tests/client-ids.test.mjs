import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { scan, redact, MASK, ScanError } from '../src/index.mjs';
import { providerKey } from './fixtures/gitleaks-credentials.mjs';
import { withLocations } from './fixtures/finding-locations.mjs';

function check(input, values, expected, policy) {
  const findings = scan(input, policy);
  assert.deepEqual(findings.map(item => input.slice(item.start, item.end)), values, input);
  for (const item of findings) {
    const description = SecretShieldRules.rules.find(rule => rule.id === item.type)?.description;
    assert.equal(item.description, description);
    assert.deepEqual(Object.keys(item).sort(), description === undefined ? ['end', 'endColumn', 'endLine', 'start', 'startColumn', 'startLine', 'type'] : ['description', 'end', 'endColumn', 'endLine', 'start', 'startColumn', 'startLine', 'type']);
  }
  assert.equal(redact(input, policy).text, expected, input);
  assert.equal(redact(input, policy).count, values.length, input);
  assert.deepEqual(scan(expected, policy), [], 'masked values are not detected again');
}

test('client-ID protection defaults on and covers explicit common field spellings', () => {
  for (const name of ['client_id', 'client-id', 'client id', 'clientId', 'CLIENTID', 'CLIENT_ID']) {
    for (const input of [`${name}=demo-client-123`, `${name}: demo-client-123`, `{"${name}":"demo-client-123"}`,
      `'${name}': 'demo-client-123'`, `config.${name}=demo-client-123`]) {
      check(input, ['demo-client-123'], input.replace('demo-client-123', MASK));
      assert.equal(scan(input)[0].type, 'client-id');
      check(input, [], input, { protectClientIds: false });
    }
  }
});

test('short, numeric and readable client-ID literals are protected in both review modes', () => {
  for (const mode of ['redact', 'block']) for (const value of ['a', '12', '311331313113', 'public-client', 'aaaaaa']) {
    const input = `client_id=${value}`;
    check(input, [value], `client_id=${MASK}`, { mode, protectClientIds: true });
    check(input, [], input, { mode, protectClientIds: false });
  }
});

test('quoted client IDs preserve escapes, multiple lines, Unicode and UTF-16 offsets', () => {
  for (const quote of ['"', "'", '`']) {
    const value = `गुप्त🔑 first\\${quote}part\\\\second, [third]\nlast`;
    const input = `😀 clientId=${quote}${value}${quote}; keep=public`;
    check(input, [value], `😀 clientId=${quote}${MASK}${quote}; keep=public`);
    const start = input.indexOf(value);
    assert.deepEqual(scan(input), withLocations(input, [{ start, end: start + value.length, type: 'client-id' }]));
  }
});

test('client-ID matching requires a complete field name and an explicit binding', () => {
  for (const input of ['other_client_id=demo', 'oauth-client-id=demo', 'client_ids=demo', 'client_identity=demo',
    '$client_id=demo', 'éclient_id=demo', 'e\u0301client_id=demo', 'client  id=demo', 'client\tid=demo',
    'client_id is demo', 'client_id\n\ndemo', 'client_id：demo', 'client_id＝demo',
    'client_id==demo', 'client_id=>demo', 'client_id::demo', 'client_id:=demo']) check(input, [], input);
  for (const newline of ['\n', '\r\n', '\r']) {
    check(`client_id:${newline}\t demo`, ['demo'], `client_id:${newline}\t ${MASK}`);
    for (const value of [`${newline}demo`, 'other_field: public', '"other field": "public"']) {
      const input = `client_id:${newline}${value}`;
      check(input, [], input);
    }
  }
});

test('client-ID placeholders, JSX expressions and already masked values are preserved', () => {
  for (const value of ['{day}', '{event.id}', '[1,2]', '(event.id)', '<VALUE>', '// comment', '# comment',
    '${CLIENT_ID}', '{{CLIENT_ID}}', 'null', 'undefined', 'true', 'false', '$CLIENT_ID', 'xxxxxxxxxx',
    '""', "''", '"   "', '"xxxxxxxxxx"', '"[REDACTED]"', '"<VALUE>"', '"${CLIENT_ID}"',
    '"{{ CLIENT_ID }}"', '`prefix-${CLIENT_ID}`']) {
    const input = `client_id=${value}`;
    check(input, [], input);
  }
});

test('toggling client-ID protection does not override saved fields or Gitleaks rules', () => {
  const input = 'client_id=demo-client-123';
  const policy = { protectClientIds: false, sensitiveNames: ['client_id'] };
  check(input, ['demo-client-123'], `client_id=${MASK}`, policy);
  assert.equal(scan(input, policy)[0].type, 'custom-field');
  for (const protectClientIds of [true, false]) {
    assert.equal(SecretShieldRules.rules.length, 217);
    const settings = { protectClientIds };
    const text = `client_id=${providerKey}`;
    check(text, [providerKey], `client_id=${MASK}`, settings);
    assert.equal(scan(text, settings)[0].type, 'github-pat');
    assert.equal(scan('client_secret=N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8', settings).length, 1);
  }
  const adobe = '0123456789abcdef'.repeat(2);
  assert.equal(scan(`adobe_client_id=${adobe}`, { protectClientIds: false })[0].type, 'adobe-client-id');
});

test('overlapping client-ID, custom and provider matches merge without masking unbound copies', () => {
  const value = `prefix ${providerKey} suffix`;
  const input = `demo\nclient_id="${value}"\ndemo\nclient-id=demo`;
  const policy = { sensitiveNames: ['client_id'] };
  check(input, [value, 'demo'], `demo\nclient_id="${MASK}"\ndemo\nclient-id=${MASK}`, policy);
  assert.equal(scan(input, policy)[0].type, 'github-pat');
  check('client_id=demo', ['demo'], `client_id=${MASK}`, policy);
});

test('incomplete client-ID literals block enabled scans and are ignored when protection is off', () => {
  for (const input of ['client_id="unfinished', "clientId='unfinished", 'client-id=`unfinished', 'client id="ends\\']) {
    assert.throws(() => scan(input), ScanError, input);
    assert.throws(() => redact(input), ScanError, input);
    check(input, [], input, { protectClientIds: false });
  }
});

test('client-ID assignment scanning remains bounded on long whitespace and repeated labels', () => {
  const script = `import assert from 'node:assert/strict';
    import {redact} from './src/index.mjs';
    const spaces=' '.repeat(100000);
    const text='client_id:\\nother_field'+spaces+': public';
    assert.equal(redact(text,undefined,text.length).text,text);
    const near=('other_client_id=public\\n').repeat(20000)+'client_id="'+'a'.repeat(200000)+'"';
    assert.equal(redact(near,undefined,near.length).text,('other_client_id=public\\n').repeat(20000)+'client_id="xxxxxxxxxx"');
    const many=('client_id=demo\\n').repeat(200000);
    assert.equal(redact(many,undefined,many.length).count,200000);`;
  execFileSync(process.execPath, ['--input-type=module', '-e', script], { cwd: new URL('..', import.meta.url), timeout: 5000, stdio: 'pipe' });
});
