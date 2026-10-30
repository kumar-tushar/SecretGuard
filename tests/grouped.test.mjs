import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { redact, scan, MASK } from '../src/index.mjs';

const first = 'Q7mV8z2R9tA4nP6xL3cD', second = 'B9wK4s8H2yF7vN5rT6aZ';
const examples = JSON.parse(await readFile(new URL('./fixtures/gitleaks-providers.json', import.meta.url), 'utf8')).examples;

test('keyword-only, grouped, natural-language and distant-value heuristics stay removed', () => {
  for (const input of [`API key at the bottom.\n${first}`, `${first}\nSome explanation.\n${second}\nAPI keys are above.`,
    `client id and client secret are\n${first}\n${second}`, 'client id and client secret are\nFdenirddvj\nGhllgdfjkg',
    `client secret is ${first}`, `api_key\n\n${first}`, `Authorization: Bearer ${first}`]) {
    assert.equal(redact(input).text, input, input);
    assert.deepEqual(scan(input), [], input);
  }
});

test('standalone provider rules detect anywhere regardless of nearby field or keyword mentions', () => {
  for (const values of Object.values(examples)) {
    const value = values[0];
    for (const input of [value, `API key at the bottom.\nSome explanation.\n${value}`,
      `${value}\nClient secret above.`, `client id and client secret are\n${first}\n${value}`]) {
      assert.equal(redact(input).text, input.replace(value, MASK));
      assert.equal(redact(input).count, 1);
    }
  }
});

test('explicit custom labels remain independent of supplemental client-ID matching', () => {
  const sensitiveNames = Array.from({ length: 50 }, (_, i) => `dataset_${i}`);
  const original = sensitiveNames.map((name, i) => `${name}=${first}${i}`).join('\n');
  for (const protectClientIds of [true, false]) {
    const policy = { sensitiveNames, protectClientIds };
    assert.equal(scan(original, policy).length, 50);
    assert.equal(redact(original, policy).text, sensitiveNames.map(name => `${name}=${MASK}`).join('\n'));
    assert.equal(redact(`client_id=${first}\n${second}`, policy).text, `client_id=${protectClientIds ? MASK : first}\n${second}`);
    assert.equal(redact(`client_secret=${first}\n${second}`, policy).text, `client_secret=${MASK}\n${second}`);
  }
});
