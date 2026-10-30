import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { redact, scan, normalizePolicy, MAX_CHARACTERS, MAX_CUSTOM_FIELDS, MASK, ScanError } from '../src/index.mjs';

const reference = JSON.parse(await readFile(new URL('./fixtures/gitleaks-providers.json', import.meta.url), 'utf8'));
const key = reference.examples['openai-api-key'][0];
const value = 'N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8';

test('default policy and saved controls retain their public interface', () => {
  assert.deepEqual(normalizePolicy(), { mode: 'redact', protectClientIds: true, sensitiveNames: [] });
  const sensitiveNames = Array.from({ length: MAX_CUSTOM_FIELDS }, (_, i) => `dataset_${i}`);
  const input = { mode: 'block', protectClientIds: false, sensitiveNames };
  const policy = normalizePolicy(input);
  assert.deepEqual(policy, input);
  assert.notEqual(policy.sensitiveNames, sensitiveNames);
  assert.deepEqual(normalizePolicy({ sensitiveNames: ['dataset_key', 'dataset_key'] }).sensitiveNames, ['dataset_key']);
  assert.equal(MAX_CUSTOM_FIELDS, 50);
  assert.equal(MASK, 'xxxxxxxxxx');
});

test('invalid text, scan limits and policies fail closed', () => {
  for (const value of [null, {}, [], 123, 'x'.repeat(MAX_CHARACTERS + 1)]) assert.throws(() => scan(value), ScanError);
  for (const policy of [{ mode: 'allow' }, { protectClientIds: 'false' }, { sensitiveNames: ['(a+)+$'] },
    { sensitiveNames: Array(MAX_CUSTOM_FIELDS + 1).fill('xx') }, { sensitiveNames: 'dataset_key' }, null, []]) {
    assert.throws(() => normalizePolicy(policy), ScanError);
  }
  for (const limit of [-1, Infinity, NaN, '100000', 1.5]) assert.throws(() => scan('text', undefined, limit), ScanError);
  assert.equal(redact('').text, '');
  assert.equal(scan('', undefined, 0).length, 0);
  assert.equal(redact('a'.repeat(MAX_CHARACTERS)).count, 0);
});

test('complete browser-sized drafts detect both generic and standalone values across the old cap', () => {
  const original = `api_key=${value}\n` + 'plain text '.repeat(10000) + `\n${key}\n` +
    'ordinary explanation '.repeat(50000) + `\nclient_secret=${value}`;
  const result = redact(original, undefined, original.length);
  assert.equal(result.count, 3);
  assert.equal(result.text, original.replaceAll(value, MASK).replace(key, MASK));
  assert.equal(scan(result.text, undefined, result.text.length).length, 0);
  assert.throws(() => redact(original), ScanError);
  assert.throws(() => redact(original, undefined, original.length - 1), ScanError);
  const crossing = 'text '.repeat(MAX_CHARACTERS / 5 - 2) + key;
  assert.equal(redact(crossing, undefined, crossing.length).text, crossing.slice(0, -key.length) + MASK);
});

test('many repeated occurrences mask exactly once each without value propagation', () => {
  const original = Array(1000).fill(`api_key="${key}"`).join('\n');
  const result = redact(original);
  assert.equal(result.count, 1000);
  assert.equal(result.text, Array(1000).fill(`api_key="${MASK}"`).join('\n'));
  assert.equal(scan(result.text).length, 0);
  assert.equal(redact(`api_key=${value}\nRepeat ${value}`).text, `api_key=${MASK}\nRepeat ${value}`);
});

test('ordinary code, placeholders and unsupported credential formats remain unchanged', () => {
  for (const text of ['Explain how API keys work.', 'const value = 123;', 'key={day}', 'key={event.id}',
    'api_key="${SERVICE_KEY}"', 'password=[REDACTED]', 'password=xxxxxxxxxx', 'Use <API_KEY> here.',
    'Authorization: Bearer opaque-value-12345', 'postgres://user:opaque-pass-998@db.example.invalid/data',
    '-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC-MATERIAL\n-----END RSA PRIVATE KEY-----']) {
    assert.equal(redact(text).text, text, text);
    assert.deepEqual(scan(text), [], text);
  }
});
