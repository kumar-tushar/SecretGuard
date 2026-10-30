import { test, expect, chromium } from '@playwright/test';
import path from 'node:path';
import { readFile } from 'node:fs/promises';

const providerKeys = JSON.parse(await readFile(new URL('../fixtures/gitleaks-providers.json', import.meta.url), 'utf8')).examples;
const structured = JSON.parse(await readFile(new URL('../fixtures/gitleaks-structured.json', import.meta.url), 'utf8')).examples;
const curl = JSON.parse(await readFile(new URL('../fixtures/gitleaks-curl.json', import.meta.url), 'utf8')).cases.filter(item => item.name.startsWith('example '));
const collaboration = JSON.parse(await readFile(new URL('../fixtures/gitleaks-collaboration.json', import.meta.url), 'utf8')).examples;
const catalog = JSON.parse(await readFile(new URL('../fixtures/gitleaks-catalog.json', import.meta.url), 'utf8')).cases;
const catalogExamples = ['azure-ad-client-secret', 'gitlab-pat', 'databricks-api-token', 'digitalocean-access-token',
  'sendgrid-api-token', 'twilio-api-key', 'postman-api-token', 'shopify-access-token', 'jwt-base64']
  .map(id => catalog.find(item => item.ruleId === id && item.secrets.length));
const normalizeLines = text => text.replace(/[\r\f]/g, '\n');

const providers = [
  ['chatgpt.com', '<textarea id="prompt-textarea"></textarea>'],
  ['claude.ai', '<div contenteditable="true" data-testid="chat-input"></div>'],
  ['gemini.google.com', '<rich-textarea><div class="ql-editor" contenteditable="true" role="textbox"></div></rich-textarea>'],
  ['chat.deepseek.com', '<textarea id="chat-input"></textarea>'],
  ['grok.com', '<div class="query-bar-editor" contenteditable="true"></div>'],
  ['www.meta.ai', '<textarea data-testid="composer-input"></textarea>'],
  ['copilot.microsoft.com', '<textarea id="userInput"></textarea>'],
  ['www.perplexity.ai', '<textarea id="ask-input"></textarea>'],
  ['chat.mistral.ai', '<div data-chat-input-bar><div class="ProseMirror" contenteditable="true"></div></div>'],
];
let context, worker, dashboard, extensionId;
test.beforeAll(async () => {
  const extension = path.resolve('dist');
  context = await chromium.launchPersistentContext('', { channel: 'chromium', headless: true, reducedMotion: 'reduce',
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`] });
  worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
  extensionId = new URL(worker.url()).hostname;
  await context.route(url => providers.some(([host]) => url.hostname === host), route => {
    const host = new URL(route.request().url()).hostname;
    const [, editor] = providers.find(([name]) => name === host);
    const label = host === 'www.perplexity.ai' ? 'Submit' : host === 'chat.mistral.ai' ? 'Send question' : 'Send message';
    const testId = host === 'grok.com' ? 'chat-submit' : 'send-button';
    return route.fulfill({ contentType: 'text/html', body: `<!doctype html><html lang="en"><head><title>Detector removal fixture</title>
      <style>[contenteditable]{display:block;min-height:100px;white-space:pre-wrap}</style></head><body><form>${editor}
      <button type="submit" data-testid="${testId}" aria-label="${label}">Send</button></form><script>
      window.sent=[];const editor=document.querySelector('textarea,[contenteditable]');
      const send=()=>window.sent.push(editor.value??editor.innerText);
      document.querySelector('form').addEventListener('submit',event=>{event.preventDefault();send()});
      editor.addEventListener('keydown',event=>{if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();send()}});
      </script></body></html>` });
  });
  dashboard = await context.newPage();
  await dashboard.goto(`chrome-extension://${extensionId}/composer.html`);
  await expect(dashboard.locator('#sensitive-names')).toBeEnabled();
});
test.afterEach(async () => {
  for (const page of context.pages()) if (page !== dashboard) await page.close();
  await dashboard.evaluate(async () => { await SecretShieldHistory.request('clear'); await chrome.storage.local.clear(); });
});
test.afterAll(async () => { await context?.close(); });

async function chat(host) {
  const page = await context.newPage();
  await page.goto(`https://${host}/`);
  const id = await worker.evaluate(async url => (await chrome.tabs.query({ url }))[0].id, page.url());
  await expect.poll(() => worker.evaluate(async id => (await chrome.tabs.sendMessage(id, { type: 'coverage' })).ready, id)).toBe(true);
  return { page, id, editor: page.locator('textarea,[contenteditable]') };
}

for (const [host] of providers) test(`${host}: retired rules leave prompts unchanged and do not open review`, async () => {
  await dashboard.evaluate(async () => {
    await SecretShieldPolicy.update({ kind: 'addField', name: 'dataset_key' });
    await SecretShieldPolicy.update({ kind: 'set', key: 'mode', value: 'block' });
  });
  const { page, editor } = await chat(host);
  const publicKey = structured['private-key'][0].replaceAll('PRIVATE KEY', 'PUBLIC KEY');
  const prompt = 'api key\n\nhju867fggfgxxjgswrxl\npassword=short\ndataset_other=synthetic-custom-123\nsk-proj-' +
    'OnlyDummy9_'.repeat(4) + '\n' + publicKey + '\neyabc.eydef.signature';
  await editor.fill(prompt);
  const original = await editor.evaluate(el => el.value ?? el.innerText);
  await editor.press('Enter');
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual([original]);
  await page.getByRole('button', { name: /^(?:Send message|Send question|Submit)$/ }).click();
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual([original, original]);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
  expect(await dashboard.evaluate(() => SecretShieldStats.read())).toEqual({ detected: 0, maskedPrompts: 0, unmaskedPrompts: 0 });
});

for (const action of ['Send', 'Edit', 'Mask']) test(`review still handles ${action} when supplied with fixture findings`, async () => {
  const { page, id, editor } = await chat('chatgpt.com');
  // Supply a fixed test finding in the isolated world; no detector is added to the build.
  await worker.evaluate(id => chrome.scripting.executeScript({ target: { tabId: id }, func: () => {
    const core = globalThis.SecretShieldCore;
    const scan = text => {
      const start = text.indexOf('fixture-only-value');
      return start < 0 ? [] : [{ start, end: start + 'fixture-only-value'.length, type: 'fixture' }];
    };
    globalThis.SecretShieldScanner = Object.freeze({ redact: async text => {
      const findings = scan(text);
      return { text: text.replace('fixture-only-value', core.MASK), count: findings.length, findings };
    } });
  } }), id);
  await editor.fill('Review fixture-only-value');
  await editor.press('Enter');
  const dialog = page.getByRole('dialog', { name: '1 secret detected', exact: true });
  await expect(dialog).toBeVisible();
  await expect(dialog.locator('.review-values code')).toHaveText(['fixture-only-value']);
  await expect(dialog.getByRole('button')).toHaveText(['Send', 'Edit', 'Mask']);
  await dialog.getByRole('button', { name: action, exact: true }).click();
  await expect(dialog).toBeHidden();
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual(action === 'Edit' ? [] :
    [action === 'Mask' ? 'Review xxxxxxxxxx' : 'Review fixture-only-value']);
  if (action === 'Edit') { await expect(editor).toHaveValue('Review fixture-only-value'); await expect(editor).toBeFocused(); }
});

const first = 'N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8', second = 'B9wK4s8H2yF7vN5rT6aZ';
const encode = text => Buffer.from(text).toString('base64');
const encodedValues = [encode(providerKeys['github-pat'][0]), encode(`api_key=${first}`),
  encode('dataset_key=12'), encode(encode(encode('client_id=demo-client-123')))];
const percent = text => [...Buffer.from(text)].map(byte => '%' + byte.toString(16).padStart(2, '0')).join('');
const percentValues = [percent(providerKeys['github-pat'][0]), percent(`api_key=${first}`),
  encode(percent('dataset_key=12')), percent(encode(percent('client_id=demo-client-123'))), first];
const hex = text => Buffer.from(text).toString('hex');
const hexValues = [hex(providerKeys['github-pat'][0]), hex(`api_key=${first}`).toUpperCase(),
  encode(hex('dataset_key=12; done')), percent(encode(hex('client_id=demo-client-123')))];
const drafts = [
  { name: 'generic', values: [first, second], text: `Keep this text.\napi_key="${first}"\nclient_secret=${second}` },
  { name: 'custom fields', fields: ['dataset_key', 'project code', 'internal-token'], values: ['12', 'some readable words', 'local-only'],
    text: 'Keep this text.\ndataset_key = 12\n{"project code":"some readable words"}\ninternal-token:\nlocal-only\nkey={event.id}' },
  { name: 'client IDs', values: ['demo-client-123', '12', 'local only'],
    text: 'Keep this text.\nclient_id = demo-client-123\n{"clientId":"12"}\nclient-id:\n"local only"\nclient id={event.id}' },
  { name: 'Base64 encoded secrets', fields: ['dataset_key'], values: encodedValues,
    text: `😀 Keep this text.\n${encodedValues.join('\n')}\nKeep this footer.` },
  { name: 'percent and mixed encoded secrets', fields: ['dataset_key'], values: percentValues,
    text: `😀 Keep this text.\n${percentValues.slice(0, 4).join('\n')}\nhttps://example.invalid/?view=public&api_key%3D${first}\nKeep this footer.` },
  { name: 'hex and mixed encoded secrets', fields: ['dataset_key'], values: hexValues,
    text: `😀 Keep this text.\n${hexValues.join('\n')}\nKeep this footer.` },
  { name: 'standalone providers', values: Object.values(providerKeys).map(values => values[0]) },
  { name: 'private keys and JWTs', values: [structured['private-key'][0], structured.jwt[0], structured.jwt[1]] },
  { name: 'cURL authorization options', values: curl.flatMap(item => item.secrets), text: curl.map(item => item.input).join('\n'.repeat(10)) },
  { name: 'Slack Stripe and npm', values: Object.values(collaboration).map(values => values[0]) },
  { name: 'extended provider catalog', values: catalogExamples.flatMap(item => item.matches ?? item.secrets).map(normalizeLines),
    text: catalogExamples.map(item => normalizeLines(item.input)).join('\n\n') },
];
for (const fixture of drafts) for (const [host] of providers) for (const action of ['Send', 'Edit', 'Mask']) test(`${host}: ${fixture.name} findings preserve ${action} for repeated Enter and click attempts`, async () => {
  if (fixture.fields) await dashboard.evaluate(async names => {
    for (const name of names) await SecretShieldPolicy.update({ kind: 'addField', name });
  }, fixture.fields);
  const { page, editor } = await chat(host), submitted = [], reviewed = [];
  const { values } = fixture, draft = fixture.text ?? values.join('\n');
  for (const trigger of ['Enter', 'click']) {
    await editor.fill(draft);
    const original = await editor.evaluate(el => el.value ?? el.innerText);
    reviewed.push(original);
    if (trigger === 'Enter') await editor.press('Enter');
    else {
      // The guard opens on pointerdown. Use the same native mouse gesture as
      // the existing submission tests, without retrying a now-covered button.
      const send = page.getByRole('button', { name: /^(?:Send message|Send question|Submit)$/ });
      await send.scrollIntoViewIfNeeded();
      const button = await send.boundingBox();
      await page.mouse.click(button.x + button.width / 2, button.y + button.height / 2);
    }
    const dialog = page.getByRole('dialog', { name: `${values.length} secrets detected`, exact: true });
    await expect(dialog).toBeVisible();
    await expect(dialog.locator('.review-values code')).toHaveText(values);
    expect(await page.evaluate(() => window.sent)).toEqual(submitted);
    await dialog.getByRole('button', { name: action, exact: true }).click();
    await expect(dialog).toBeHidden();
    if (action === 'Edit') {
      expect(await editor.evaluate(el => el.value ?? el.innerText)).toBe(original);
      await expect(editor).toBeFocused();
    } else submitted.push(action === 'Send' ? original : values.reduce((text, value) => text.replace(value, 'xxxxxxxxxx'), original));
    await expect.poll(() => page.evaluate(() => window.sent)).toEqual(submitted);
  }
  await expect.poll(() => dashboard.evaluate(() => SecretShieldStats.read())).toEqual({
    detected: values.length * 2, maskedPrompts: action === 'Mask' ? 2 : 0, unmaskedPrompts: action === 'Send' ? 2 : 0,
  });
  const history = await dashboard.evaluate(() => SecretShieldHistory.request('list'));
  expect(history).toHaveLength(action === 'Send' ? 2 : 0);
  for (const entry of history) {
    expect(await dashboard.evaluate(id => SecretShieldHistory.readPrompt(id), entry.id)).toBe(reviewed[0]);
    expect(entry.count).toBe(values.length);
  }
});

for (const host of ['chatgpt.com', 'claude.ai']) test(`${host}: strict mode masks complete nested Base64 segments`, async () => {
  await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'set', key: 'mode', value: 'block' }));
  const { page, editor } = await chat(host), value = encode(encode(`api_key=${first}`));
  await editor.fill(`Before.\n${value}\nAfter.`);
  await editor.press('Enter');
  const dialog = page.getByRole('dialog');
  await expect(dialog.locator('.review-values code')).toHaveText([value]);
  await expect(dialog.getByRole('button', { name: 'Send', exact: true })).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Mask', exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual(['Before.\nxxxxxxxxxx\nAfter.']);
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
});

test('decoded client IDs respect the setting and explicit custom fields in the worker', async () => {
  await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'set', key: 'protectClientIds', value: false }));
  const { page, editor } = await chat('chatgpt.com'), value = encode('client_id=demo-client-123');
  await editor.fill(value);
  await editor.press('Enter');
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual([value]);
  await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'addField', name: 'client_id' }));
  await page.close();
  const next = await chat('chatgpt.com');
  await next.editor.fill(value);
  await next.editor.press('Enter');
  const dialog = next.page.getByRole('dialog');
  await expect(dialog.locator('.review-values code')).toHaveText([value]);
  await dialog.getByRole('button', { name: 'Mask', exact: true }).click();
  await expect.poll(() => next.page.evaluate(() => window.sent)).toEqual(['xxxxxxxxxx']);
});

test('exhausting the Base64 budget preserves the complete draft and blocks sending', async () => {
  const { page, editor } = await chat('chatgpt.com'), draft = encode('^'.repeat(1_000_001));
  await editor.fill(draft);
  await editor.press('Enter');
  await expect(page.locator('#secret-shield-notice')).toBeVisible({ timeout: 7000 });
  await expect(editor).toHaveValue(draft);
  expect(await page.evaluate(() => window.sent)).toEqual([]);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
  expect(await dashboard.evaluate(() => SecretShieldStats.read())).toEqual({ detected: 0, maskedPrompts: 0, unmaskedPrompts: 0 });
});

for (const host of ['chatgpt.com', 'claude.ai']) test(`${host}: strict mode masks complete mixed percent/Base64 segments`, async () => {
  await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'set', key: 'mode', value: 'block' }));
  const { page, editor } = await chat(host), value = percent(encode(percent(`api_key=${first}`)));
  await editor.fill(`Before.\n${value}\nAfter.`);
  await editor.press('Enter');
  const dialog = page.getByRole('dialog');
  await expect(dialog.locator('.review-values code')).toHaveText([value]);
  await expect(dialog.getByRole('button', { name: 'Send', exact: true })).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Mask', exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual(['Before.\nxxxxxxxxxx\nAfter.']);
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
});

test('percent-encoded client IDs respect the setting and explicit custom fields in the worker', async () => {
  await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'set', key: 'protectClientIds', value: false }));
  const { page, editor } = await chat('chatgpt.com'), value = percent('client_id=demo-client-123');
  await editor.fill(value);
  await editor.press('Enter');
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual([value]);
  await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'addField', name: 'client_id' }));
  await page.close();
  const next = await chat('chatgpt.com');
  await next.editor.fill(value);
  await next.editor.press('Enter');
  const dialog = next.page.getByRole('dialog');
  await expect(dialog.locator('.review-values code')).toHaveText([value]);
  await dialog.getByRole('button', { name: 'Mask', exact: true }).click();
  await expect.poll(() => next.page.evaluate(() => window.sent)).toEqual(['xxxxxxxxxx']);
});

test('exhausting the percent-decoding budget preserves the complete draft and blocks sending', async () => {
  const { page, editor } = await chat('chatgpt.com'), draft = '%5E'.repeat(1_000_001);
  await editor.fill(draft);
  await editor.press('Enter');
  await expect(page.locator('#secret-shield-notice')).toBeVisible({ timeout: 7000 });
  await expect(editor).toHaveValue(draft);
  expect(await page.evaluate(() => window.sent)).toEqual([]);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
  expect(await dashboard.evaluate(() => SecretShieldStats.read())).toEqual({ detected: 0, maskedPrompts: 0, unmaskedPrompts: 0 });
});

for (const host of ['chatgpt.com', 'claude.ai']) test(`${host}: strict mode masks complete mixed hex/percent/Base64 segments`, async () => {
  await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'set', key: 'mode', value: 'block' }));
  const { page, editor } = await chat(host), value = hex(encode(percent(`api_key=${first}`)));
  await editor.fill(`Before.\n${value}\nAfter.`);
  await editor.press('Enter');
  const dialog = page.getByRole('dialog');
  await expect(dialog.locator('.review-values code')).toHaveText([value]);
  await expect(dialog.getByRole('button', { name: 'Send', exact: true })).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Mask', exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual(['Before.\nxxxxxxxxxx\nAfter.']);
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
});

test('hex-encoded client IDs respect the setting and explicit custom fields in the worker', async () => {
  await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'set', key: 'protectClientIds', value: false }));
  const { page, editor } = await chat('chatgpt.com'), value = hex('client_id=demo-client-123');
  await editor.fill(value);
  await editor.press('Enter');
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual([value]);
  await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'addField', name: 'client_id' }));
  await page.close();
  const next = await chat('chatgpt.com');
  await next.editor.fill(value);
  await next.editor.press('Enter');
  const dialog = next.page.getByRole('dialog');
  await expect(dialog.locator('.review-values code')).toHaveText([value]);
  await dialog.getByRole('button', { name: 'Mask', exact: true }).click();
  await expect.poll(() => next.page.evaluate(() => window.sent)).toEqual(['xxxxxxxxxx']);
});

test('exhausting the hex-decoding budget preserves the complete draft and blocks sending', async () => {
  const { page, editor } = await chat('chatgpt.com'), draft = '5e'.repeat(1_000_001);
  await editor.fill(draft);
  await editor.press('Enter');
  await expect(page.locator('#secret-shield-notice')).toBeVisible({ timeout: 7000 });
  await expect(editor).toHaveValue(draft);
  expect(await page.evaluate(() => window.sent)).toEqual([]);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
  expect(await dashboard.evaluate(() => SecretShieldStats.read())).toEqual({ detected: 0, maskedPrompts: 0, unmaskedPrompts: 0 });
});

for (const host of ['chatgpt.com', 'claude.ai']) test(`${host}: strict mode masks every option in repeated cURL commands`, async () => {
  await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'set', key: 'mode', value: 'block' }));
  const { page, editor } = await chat(host), token = 'N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8';
  const draft = `curl -u first-user:${token} --user second-user:${token}\ncurl -H "Authorization: Bearer ${token}" -H "X-Api-Key: ${token}"`;
  await editor.fill(draft);
  await editor.press('Enter');
  const dialog = page.getByRole('dialog');
  await expect(dialog.locator('.review-values code')).toHaveText([`first-user:${token}`, `second-user:${token}`, token, token]);
  await expect(dialog.getByRole('button', { name: 'Send', exact: true })).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Mask', exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual([
    'curl -u xxxxxxxxxx --user xxxxxxxxxx\ncurl -H "Authorization: Bearer xxxxxxxxxx" -H "X-Api-Key: xxxxxxxxxx"',
  ]);
});

for (const host of ['chatgpt.com', 'claude.ai']) test(`${host}: strict mode masks complete private keys and JWTs`, async () => {
  await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'set', key: 'mode', value: 'block' }));
  const { page, editor } = await chat(host);
  const values = [structured['private-key'][0], structured.jwt[0]], draft = values.join('\n\n');
  await editor.fill(draft);
  const original = await editor.evaluate(el => el.value ?? el.innerText);
  await editor.press('Enter');
  const dialog = page.getByRole('dialog');
  await expect(dialog.locator('.review-values code')).toHaveText(values);
  await expect(dialog.getByRole('button', { name: 'Send', exact: true })).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Mask', exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual([values.reduce((text, value) => text.replace(value, 'xxxxxxxxxx'), original)]);
});

for (const host of ['claude.ai', 'gemini.google.com']) test(`${host}: multiline replacement preserves intentional blank lines and styled surrounding text`, async () => {
  const { page, editor } = await chat(host), key = structured['private-key'][0], submitted = [];
  const [header, body, footer] = key.split('\n');
  for (const html of [
    `${header}<div>${body}</div><div>${footer}</div><div><br></div><div><strong>Keep this style.</strong></div>`,
    `<p>Before</p><p>${header}</p><p>${body}</p><p>${footer}</p><p><br></p><p><strong>Keep this style.</strong></p>`,
    `${header}<br>${body}<br>${footer}<br><br><strong>Keep this style.</strong>`,
  ]) {
    await editor.evaluate((el, html) => { el.innerHTML = html; el.dispatchEvent(new InputEvent('input', { bubbles: true })); }, html);
    const before = await editor.innerText();
    const start = before.indexOf(header), end = before.indexOf(footer) + footer.length;
    await editor.press('Enter');
    const dialog = page.getByRole('dialog');
    await expect(dialog.locator('.review-values code')).toHaveText([before.slice(start, end)]);
    await dialog.getByRole('button', { name: 'Mask', exact: true }).click();
    submitted.push(before.slice(0, start) + 'xxxxxxxxxx' + before.slice(end));
    await expect.poll(() => page.evaluate(() => window.sent)).toEqual(submitted);
    await expect(editor.locator('strong')).toHaveText('Keep this style.');
    await expect(page.locator('#secret-shield-notice')).toHaveCount(0);
  }
});

test('a rejected extra-line-break correction never submits a partially updated draft', async () => {
  const { page, id, editor } = await chat('claude.ai');
  await worker.evaluate(id => chrome.scripting.executeScript({ target: { tabId: id }, func: () => {
    const exec = document.execCommand.bind(document);
    document.execCommand = (command, ui, value) => command === 'insertText' && value === '\n' ? false : exec(command, ui, value);
  } }), id);
  await editor.fill(structured['private-key'][0] + '\nKeep this text.');
  await editor.press('Enter');
  await page.getByRole('dialog').getByRole('button', { name: 'Mask', exact: true }).click();
  await expect(page.locator('#secret-shield-notice')).toBeVisible();
  expect(await page.evaluate(() => window.sent)).toEqual([]);
  expect((await dashboard.evaluate(() => SecretShieldStats.read())).maskedPrompts).toBe(0);
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
});

test('custom-field detection preserves strict mode and the current modal design', async () => {
  await dashboard.evaluate(async () => {
    await SecretShieldPolicy.update({ kind: 'addField', name: 'dataset_name' });
    await SecretShieldPolicy.update({ kind: 'set', key: 'mode', value: 'block' });
  });
  const { page, editor } = await chat('claude.ai');
  await editor.fill(`dataset_name=12\napi_key=${first}`); await editor.press('Enter');
  const dialog = page.getByRole('dialog');
  await expect(dialog.locator('.review-values code')).toHaveText(['12', first]);
  await expect(dialog.getByRole('button', { name: 'Send', exact: true })).toHaveCount(0);
  await expect(dialog.getByRole('button', { name: 'Mask', exact: true })).toHaveCSS('background-color', 'rgb(69, 214, 200)');
  await expect(dialog.getByRole('button', { name: 'Mask', exact: true })).toHaveCSS('height', '34px');
  await dialog.getByRole('button', { name: 'Mask', exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual(['dataset_name=xxxxxxxxxx\napi_key=xxxxxxxxxx']);
  expect(await dashboard.evaluate(async () => (await SecretShieldPolicy.loadPolicy()).policy.sensitiveNames)).toEqual(['dataset_name']);
  await editor.fill('key={event.id}\nExplain how API keys work.'); await editor.press('Enter');
  await expect(dialog).toBeHidden();
  await expect.poll(() => page.evaluate(() => window.sent)).toHaveLength(2);
});

for (const field of ['dataset_key', 'client_id']) for (const [host] of providers) test(`${host}: incomplete ${field} literals are kept local`, async () => {
  if (field === 'dataset_key') await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'addField', name: 'dataset_key' }));
  const { page, editor } = await chat(host);
  await editor.fill(`${field}="unfinished value`);
  await editor.press('Enter');
  await expect(page.locator('#secret-shield-notice')).toBeVisible();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(await page.evaluate(() => window.sent)).toEqual([]);
  expect(await dashboard.evaluate(() => SecretShieldStats.read())).toEqual({ detected: 0, maskedPrompts: 0, unmaskedPrompts: 0 });
});
