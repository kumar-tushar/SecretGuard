import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { scan, redact, MASK, ScanError } from '../src/index.mjs';

const policy = { sensitiveNames: ['dataset_key', 'project code', 'internal-token'] };

function check(input, values, expected, settings = policy) {
  const findings = scan(input, settings);
  assert.deepEqual(findings.map(item => input.slice(item.start, item.end)), values, input);
  for (const item of findings) assert.deepEqual(Object.keys(item).sort(), ['end', 'start', 'type']);
  const result = redact(input, settings);
  assert.equal(result.text, expected, input);
  assert.equal(result.count, values.length, input);
  assert.deepEqual(scan(result.text, settings), [], 'masked values are not detected again');
}

test('saved names detect explicit assignments and quoted JSON properties', () => {
  for (const input of ['dataset_key=value', 'dataset_key: value', 'DATASET_KEY = value', 'config.dataset_key=value',
    '{"dataset_key":"value"}', "{'dataset_key': 'value'}", '`dataset_key`: `value`', 'project code=value', 'internal-token:value']) {
    check(input, ['value'], input.replace('value', MASK));
    assert.equal(scan(input, policy)[0].type, 'custom-field');
  }
});

test('custom fields deliberately protect short, numeric and readable literal values', () => {
  for (const value of ['a', '12', '311331313113', 'password', 'hello', 'aaaaaa', 'example-value']) {
    check(`dataset_key=${value}`, [value], `dataset_key=${MASK}`);
  }
  check('dataset_key="some readable words"', ['some readable words'], `dataset_key="${MASK}"`);
  check('dataset_key="false"', ['false'], `dataset_key="${MASK}"`);
});

test('names are matched literally without aliases or identifier substrings', () => {
  for (const input of ['datasetKey=value', 'dataset-key=value', 'dataset key=value', 'other_dataset_key=value',
    'other-dataset_key=value', 'dataset_key_other=value', '$dataset_key=value', 'Adataset_key=value',
    'éDataset_key=value', '中dataset_key=value', 'e\u0301dataset_key=value', 'dataset_keyOther=value']) {
    check(input, [], input);
  }
  check('project code=value; project_code=public', ['value'], `project code=${MASK}; project_code=public`);
});

test('quoted literals preserve wrappers, escapes, punctuation and following text', () => {
  for (const quote of ['"', "'", '`']) {
    const value = `a\\${quote}b\\\\c, d; [e] {f}: g=value`;
    const input = `dataset_key=${quote}${value}${quote}; keep=this`;
    check(input, [value], `dataset_key=${quote}${MASK}${quote}; keep=this`);
  }
  check('dataset_key="first\nsecond"\nKeep this.', ['first\nsecond'], `dataset_key="${MASK}"\nKeep this.`);
  check('dataset_key=value; other=public', ['value'], `dataset_key=${MASK}; other=public`);
  check('<input dataset_key=value>', ['value'], `<input dataset_key=${MASK}>`);
});

test('UTF-16 offsets replace complete Unicode literals without changing surrounding text', () => {
  const value = 'गुप्त🔑é', input = `😀 हिन्दी dataset_key="${value}". Keep 🔐.`;
  const start = input.indexOf(value);
  assert.deepEqual(scan(input, policy), [{ start, end: start + value.length, type: 'custom-field' }]);
  check(input, [value], `😀 हिन्दी dataset_key="${MASK}". Keep 🔐.`);
});

test('only an explicit separator can bind a value on the immediately following line', () => {
  for (const separator of [':', '=']) for (const newline of ['\n', '\r\n', '\r']) {
    const input = `dataset_key${separator}${newline}\t value`;
    check(input, ['value'], `dataset_key${separator}${newline}\t ${MASK}`);
  }
  for (const input of ['dataset_key\nvalue', 'dataset_key\n\nvalue', 'dataset_key:\n\nvalue',
    'dataset_key=\n \nvalue', 'dataset_key is value', 'dataset_key：value', 'dataset_key＝value',
    'dataset_key:\nother_field: public', 'dataset_key=\n"other field": "public"', 'dataset_key:']) check(input, [], input);
  check('dataset_key:\ninternal-token: value', ['value'], `dataset_key:\ninternal-token: ${MASK}`);
});

test('JSX, object expressions, placeholders and already masked values are skipped', () => {
  for (const value of ['{day}', '{event.id}', '[1,2]', '(event.id)', '<VALUE>', '// comment', '# comment',
    '${ENV_VALUE}', '{{ENV_VALUE}}', 'null', 'undefined', 'true', 'false', '$ENV_VALUE', 'xxxxxxxxxx',
    '""', "''", '"   "', '"xxxxxxxxxx"', '"[REDACTED]"', '"<VALUE>"', '"${ENV_VALUE}"',
    '"{{ ENV_VALUE }}"', '`prefix-${ENV_VALUE}`']) {
    const input = `dataset_key=${value}`;
    check(input, [], input);
  }
  for (const input of ['dataset_key==value', 'dataset_key=>value', 'dataset_key::value', 'dataset_key:=value']) check(input, [], input);
});

test('custom values do not infer other values or mask equal unbound occurrences', () => {
  const input = 'value\ndataset_key=value\nvalue\nother_name=value\ndataset_key="value"';
  check(input, ['value', 'value'], `value\ndataset_key=${MASK}\nvalue\nother_name=value\ndataset_key="${MASK}"`);
  check('dataset_key="internal-token=public"', ['internal-token=public'], `dataset_key="${MASK}"`);
});

test('removing or changing a saved name takes effect on the next scan', () => {
  const input = 'dataset_key=short; project code=other';
  check(input, [], input, {});
  check(input, ['short'], `dataset_key=${MASK}; project code=other`, { sensitiveNames: ['dataset_key'] });
  check(input, ['other'], `dataset_key=short; project code=${MASK}`, { sensitiveNames: ['project code'] });
  check(input, [], input, { sensitiveNames: [] });
});

test('custom policy applies in both review modes independently of the client-ID preference', () => {
  for (const mode of ['redact', 'block']) for (const protectClientIds of [true, false]) {
    const settings = { ...policy, mode, protectClientIds };
    check('dataset_key=12', ['12'], `dataset_key=${MASK}`, settings);
  }
});

test('all 50 custom fields and case duplicates produce one item per bound occurrence', () => {
  const sensitiveNames = Array.from({ length: 50 }, (_, i) => `field_${i}`);
  const input = sensitiveNames.map((name, i) => `${name}=${i}`).join('\n');
  check(input, sensitiveNames.map((_, i) => String(i)), sensitiveNames.map(name => `${name}=${MASK}`).join('\n'), { sensitiveNames });
  check('dataset_key=value', ['value'], `dataset_key=${MASK}`, { sensitiveNames: ['DATASET_KEY', 'dataset_key'] });
});

test('Gitleaks and custom matches merge overlapping ranges without changing the rule catalog', () => {
  assert.equal(SecretShieldRules.rules.length, 217);
  const key = 'sk-' + 'N7q2V9m4R8s6T3x5K1p0' + 'T3BlbkFJ' + 'L2z7H4c9D6b8B9wK4s8H';
  check(`dataset_key="prefix ${key} suffix"`, [`prefix ${key} suffix`], `dataset_key="${MASK}"`);
  assert.equal(scan(`dataset_key="prefix ${key} suffix"`, policy)[0].type, 'openai-api-key');
  const value = 'Q7mV8z2R9tA4nP6xL3cD';
  check(`api_key=${value}`, [value], `api_key=${MASK}`, { sensitiveNames: ['api_key'] });
  check(`dataset_key=${key}\n${key}`, [key, key], `dataset_key=${MASK}\n${MASK}`);
});

test('incomplete quoted custom values fail closed instead of masking only a prefix', () => {
  for (const input of ['dataset_key="unfinished', "dataset_key='unfinished", 'dataset_key=`unfinished', 'dataset_key="ends\\']) {
    assert.throws(() => scan(input, policy), ScanError, input);
    assert.throws(() => redact(input, policy), ScanError, input);
    assert.deepEqual(scan(input), [], 'unset fields do not change scanning');
  }
});

test('long custom values, many near labels and escaped strings have bounded execution', () => {
  const script = `import assert from 'node:assert/strict';
    import {redact} from './src/index.mjs';
    const sensitiveNames=Array.from({length:50},(_,i)=>'field_'+i);
    const policy={sensitiveNames};
    const text=('field_490: public\\n').repeat(30000)+'field_49="'+'a\\\\b'.repeat(100000)+'"';
    const result=redact(text,policy,text.length);
    assert.equal(result.count,1);
    assert.equal(result.text,('field_490: public\\n').repeat(30000)+'field_49="xxxxxxxxxx"');
    const spaces=' '.repeat(100000);
    const nextLine='field_49:\\na'+spaces+'b';
    assert.equal(redact(nextLine,policy,nextLine.length).text,'field_49:\\nxxxxxxxxxx'+spaces+'b');
    const nextField='field_49:\\nother_field'+spaces+': public';
    assert.equal(redact(nextField,policy,nextField.length).text,nextField);`;
  execFileSync(process.execPath, ['--input-type=module', '-e', script], { cwd: new URL('..', import.meta.url), timeout: 5000, stdio: 'pipe' });
});
