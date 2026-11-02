import { test, expect, chromium } from '@playwright/test';
import { cp, mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';

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
const providerKey = JSON.parse(await readFile(new URL('../fixtures/gitleaks-providers.json', import.meta.url), 'utf8')).examples['github-pat'][0];
const value = 'N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8', other = 'B9wK4s8H2yF7vN5rT6aZ';
const exception = { targetRules: ['generic-api-key', 'curl-auth-user'], condition: 'OR', regexTarget: 'secret',
  regexes: [`^(?:${value}|service:${value}|${providerKey})$`], stopwords: [], paths: [] };
const allowed = `api_key=${value}\ncurl -u service:${value} https://example.invalid`;
const draft = `Keep this.\n${allowed}\napi_key=${providerKey}\ndataset_key=${value}\nclient_id=public-client-id\napi_key=${other}\nEnd.`;
const reviewed = [providerKey, value, 'public-client-id', other];
const masked = `Keep this.\n${allowed}\napi_key=xxxxxxxxxx\ndataset_key=xxxxxxxxxx\nclient_id=xxxxxxxxxx\napi_key=xxxxxxxxxx\nEnd.`;
let directory, context, worker, dashboard;
test.beforeAll(async () => {
  directory = await mkdtemp('/tmp/ckretguard-allowlist-browser-');
  await cp(path.resolve('dist'), directory, { recursive: true });
  // Only this private fixture has configured exceptions; the production catalog
  // and its default detections are unchanged.
  const rules = path.join(directory, 'gitleaks-rules.js');
  await writeFile(rules, await readFile(rules, 'utf8') + `\nSecretShieldRules.globalAllowlists.push(${JSON.stringify(exception)});\n`);
  const workerFile = path.join(directory, 'scan-worker.js');
  await writeFile(workerFile, await readFile(workerFile, 'utf8') + `
    const actualScan = self.onmessage;
    self.onmessage = event => {
      if (event.data.text.startsWith('INVALID_TARGET\\n')) {
        SecretShieldRules.globalAllowlists.push({targetRules:['unknown-rule'],regexes:['.*'],stopwords:[],paths:[]});
      }
      actualScan(event);
    };`);
  context = await chromium.launchPersistentContext('', { channel: 'chromium', headless: true, reducedMotion: 'reduce',
    args: ['--disable-extensions-except=' + directory, '--load-extension=' + directory] });
  worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
  const id = new URL(worker.url()).hostname;
  await context.route(url => providers.some(([host]) => url.hostname === host), route => {
    const host = new URL(route.request().url()).hostname, editor = providers.find(([name]) => name === host)[1];
    const label = host === 'www.perplexity.ai' ? 'Submit' : host === 'chat.mistral.ai' ? 'Send question' : 'Send message';
    return route.fulfill({ contentType: 'text/html', body: `<!doctype html><html><head><title>Shared allowlist fixture</title>
      <style>[contenteditable]{min-height:100px;white-space:pre-wrap}</style></head><body><form>${editor}
      <button type="submit" data-testid="${host === 'grok.com' ? 'chat-submit' : 'send-button'}" aria-label="${label}">Send</button></form><script>
      window.sent=[];const editor=document.querySelector('textarea,[contenteditable]');
      const send=()=>window.sent.push(editor.value??editor.innerText);
      editor.addEventListener('keydown',event=>{if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();send();}});
      document.querySelector('form').addEventListener('submit',event=>{event.preventDefault();send();});
      </script></body></html>` });
  });
  dashboard = await context.newPage();
  await dashboard.goto(`chrome-extension://${id}/composer.html`);
  await expect(dashboard.locator('#sensitive-names')).toBeEnabled();
});
test.afterEach(async () => {
  for (const page of context.pages()) if (page !== dashboard) await page.close();
  await dashboard.evaluate(async () => { await SecretShieldHistory.request('clear'); await chrome.storage.local.clear(); });
});
test.afterAll(async () => { await context?.close(); if (directory) await rm(directory, { recursive: true, force: true }); });
async function chat(host = 'chatgpt.com') {
  const page = await context.newPage();
  await page.goto(`https://${host}/`);
  const id = await worker.evaluate(async url => (await chrome.tabs.query({ url }))[0].id, page.url());
  await expect.poll(() => worker.evaluate(async id => (await chrome.tabs.sendMessage(id, { type: 'coverage' })).ready, id)).toBe(true);
  return { page, editor: page.locator('textarea,[contenteditable]') };
}

for (const [host] of providers) for (const action of ['Send', 'Edit', 'Mask']) test(`${host}: shared exclusions preserve untargeted findings and ${action}`, async () => {
  await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'addField', name: 'dataset_key' }));
  const { page, editor } = await chat(host);
  await editor.fill(draft);
  await editor.press('Enter');
  const dialog = page.getByRole('dialog', { name: '4 secrets detected', exact: true });
  await expect(dialog.locator('.review-values code')).toHaveText(reviewed);
  expect(await page.evaluate(() => window.sent)).toEqual([]);
  await dialog.getByRole('button', { name: action, exact: true }).click();
  await expect(dialog).toBeHidden();
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual(action === 'Edit' ? [] : [action === 'Send' ? draft : masked]);
  if (action === 'Edit') expect(await editor.evaluate(el => el.value ?? el.innerText)).toBe(draft);
  await expect.poll(() => dashboard.evaluate(() => SecretShieldStats.read())).toEqual({ detected: 4,
    maskedPrompts: action === 'Mask' ? 1 : 0, unmaskedPrompts: action === 'Send' ? 1 : 0 });
  const history = await dashboard.evaluate(() => SecretShieldHistory.request('list'));
  expect(history).toHaveLength(action === 'Send' ? 1 : 0);
  if (history.length) {
    expect(history[0].count).toBe(4);
    expect(await dashboard.evaluate(id => SecretShieldHistory.readPrompt(id), history[0].id)).toBe(draft);
  }
});

for (const host of ['chatgpt.com', 'claude.ai']) test(`${host}: strict mode masks retained encoded findings and respects scoped exceptions`, async () => {
  await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'set', key: 'mode', value: 'block' }));
  const { page, editor } = await chat(host);
  const excluded = Buffer.from(`api_key=${value}`).toString('hex'), retained = Buffer.from(`api_key=${providerKey}`).toString('base64');
  await editor.fill(`${excluded}\n${retained}`);
  await editor.press('Enter');
  const dialog = page.getByRole('dialog');
  await expect(dialog.locator('.review-values code')).toHaveText([retained]);
  await expect(dialog.getByRole('button', { name: 'Send', exact: true })).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Mask', exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual([`${excluded}\nxxxxxxxxxx`]);
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
});

test('a prompt containing only scoped exceptions sends unchanged without review or activity', async () => {
  const { page, editor } = await chat();
  await editor.fill(allowed);
  await editor.press('Enter');
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual([allowed]);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
  expect(await dashboard.evaluate(() => SecretShieldStats.read())).toEqual({ detected: 0, maskedPrompts: 0, unmaskedPrompts: 0 });
});

test('an unknown shared target fails closed and a fresh valid worker can retry', async () => {
  const { page, editor } = await chat(), input = `INVALID_TARGET\n${allowed}`;
  await editor.fill(input);
  await editor.press('Enter');
  await expect(page.locator('#secret-shield-notice')).toBeVisible();
  await expect(editor).toHaveValue(input);
  expect(await page.evaluate(() => window.sent)).toEqual([]);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
  expect(await dashboard.evaluate(() => SecretShieldStats.read())).toEqual({ detected: 0, maskedPrompts: 0, unmaskedPrompts: 0 });
  await editor.fill(allowed);
  await editor.press('Enter');
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual([allowed]);
});
