import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { redact, scan, MASK } from '../src/index.mjs';
import { plainCases } from './fixtures/credentials.mjs';

const examples = JSON.parse(await readFile(new URL('./fixtures/gitleaks-providers.json', import.meta.url), 'utf8')).examples;

test('enabled provider catalog masks exact values and preserves surrounding text', () => {
  for (const [type, values] of Object.entries(examples)) for (const value of values) {
    for (const input of [`Inspect ${value}`, `api_key="${value}"`, `説明 🔐\r\n${value}\r\nपुनः ${value}`]) {
      const result = redact(input, { sensitiveNames: ['dataset_key'] });
      assert.equal(result.text, input.replaceAll(value, MASK), type);
      assert.equal(result.count, input.split(value).length - 1, type);
      assert.ok(result.findings.every(finding => finding.type === type));
      assert.equal(redact(result.text).count, 0);
    }
  }
  for (const input of plainCases) assert.equal(redact(input).text, input, input);
});

test('10,000 seeded assignment combinations preserve Gitleaks scope and mask idempotently', () => {
  let seed = 0xC0FFEE;
  const pick = values => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return values[seed % values.length]; };
  const values = Object.values(examples).flat();
  for (let i = 0; i < 10_000; i++) {
    const value = pick(values), label = pick(['api_key', 'token', 'client_secret', 'password', 'creds']);
    const separator = pick([': ', ' = ', '=>', '::=', '?=', ', ']);
    const quote = pick(['', '"', "'", '`']);
    const input = `Keep 🧪 ${label}${separator}${quote}${value}${quote}\nKeep this sentence.`;
    const result = redact(input);
    assert.equal(result.text, input.replace(value, MASK), `case ${i}`);
    assert.equal(result.count, 1, `case ${i}`);
    assert.equal(scan(result.text).length, 0, `case ${i}`);
  }
});
