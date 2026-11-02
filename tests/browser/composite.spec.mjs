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
const common = { secretGroup: 1, entropy: 0, keywords: [], allowlists: [] };
const rules = [
  { ...common, id: 'fixture-primary', regex: 'credential=([A-Z][A-Z0-9]{5,})',
    required: [{ id: 'fixture-context', withinLines: 1 }, { id: 'fixture-region' }] },
  { ...common, id: 'fixture-context', regex: '(SERVICE)', skipReport: true },
  { ...common, id: 'fixture-region', regex: '(REGION)', skipReport: true },
];
const draft = 'SERVICE\nREGION credential=ABC123\nKeep.\ncredential=DEF456\nEnd.';
const masked = draft.replace('ABC123', 'xxxxxxxxxx');
let directory, context, worker, dashboard;
test.beforeAll(async () => {
  directory = await mkdtemp('/tmp/ckretguard-composite-browser-');
  await cp(path.resolve('dist'), directory, { recursive: true });
  // Composite examples are confined to this private fixture. No production
  // catalog rule gains a dependency or a hidden reporting flag.
  const catalog = path.join(directory, 'gitleaks-rules.js');
  await writeFile(catalog, await readFile(catalog, 'utf8') + `\nSecretShieldRules.rules.push(...${JSON.stringify(rules)});\n`);
  const workerFile = path.join(directory, 'scan-worker.js');
  await writeFile(workerFile, await readFile(workerFile, 'utf8') + `
    const actualScan = self.onmessage;
    self.onmessage = event => {
      const rule = SecretShieldRules.rules.find(rule => rule.id === 'fixture-primary');
      if (event.data.text.startsWith('INVALID_REQUIRED\\n')) rule.required = [{id:'unknown-rule'}];
      if (event.data.text.startsWith('COMPARISON_LIMIT\\n')) rule.required = Array(1001).fill({id:'fixture-context'});
      actualScan(event);
    };`);
  context = await chromium.launchPersistentContext('', { channel: 'chromium', headless: true, reducedMotion: 'reduce',
    args: ['--disable-extensions-except=' + directory, '--load-extension=' + directory] });
  worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
  const id = new URL(worker.url()).hostname;
  await context.route(url => providers.some(([host]) => url.hostname === host), route => {
    const host = new URL(route.request().url()).hostname, editor = providers.find(([name]) => name === host)[1];
    const label = host === 'www.perplexity.ai' ? 'Submit' : host === 'chat.mistral.ai' ? 'Send question' : 'Send message';
    return route.fulfill({ contentType: 'text/html', body: `<!doctype html><html><head><title>Composite rule fixture</title>
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

for (const [host] of providers) for (const action of ['Send', 'Edit', 'Mask']) test(`${host}: only a supported primary reaches review and ${action}`, async () => {
  const { page, editor } = await chat(host);
  await editor.fill(draft);
  await editor.press('Enter');
  const dialog = page.getByRole('dialog', { name: '1 secret detected', exact: true });
  await expect(dialog.locator('.review-values code')).toHaveText(['ABC123']);
  expect(await page.evaluate(() => window.sent)).toEqual([]);
  await dialog.getByRole('button', { name: action, exact: true }).click();
  await expect(dialog).toBeHidden();
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual(action === 'Edit' ? [] : [action === 'Send' ? draft : masked]);
  if (action === 'Edit') expect(await editor.evaluate(el => el.value ?? el.innerText)).toBe(draft);
  await expect.poll(() => dashboard.evaluate(() => SecretShieldStats.read())).toEqual({ detected: 1,
    maskedPrompts: action === 'Mask' ? 1 : 0, unmaskedPrompts: action === 'Send' ? 1 : 0 });
  const history = await dashboard.evaluate(() => SecretShieldHistory.request('list'));
  expect(history).toHaveLength(action === 'Send' ? 1 : 0);
  if (history.length) {
    expect(history[0].count).toBe(1);
    expect(await dashboard.evaluate(id => SecretShieldHistory.readPrompt(id), history[0].id)).toBe(draft);
  }
});

for (const host of ['chatgpt.com', 'claude.ai']) test(`${host}: strict mode reviews and masks the original encoded composite span`, async () => {
  await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'set', key: 'mode', value: 'block' }));
  const { page, editor } = await chat(host), encoded = Buffer.from('SERVICE REGION credential=ABC123').toString('base64');
  await editor.fill(`Keep.\n${encoded}\nEnd.`);
  await editor.press('Enter');
  const dialog = page.getByRole('dialog');
  await expect(dialog.locator('.review-values code')).toHaveText([encoded]);
  await expect(dialog.getByRole('button', { name: 'Send', exact: true })).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Mask', exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.sent)).toEqual(['Keep.\nxxxxxxxxxx\nEnd.']);
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
});

test('support-only and incomplete or distant composites send unchanged without review or activity', async () => {
  const { page, editor } = await chat();
  const inputs = ['SERVICE REGION', 'SERVICE credential=ABC123', 'SERVICE\nREGION\ncredential=ABC123'];
  for (const [index, input] of inputs.entries()) {
    await editor.fill(input);
    await editor.press('Enter');
    await expect.poll(() => page.evaluate(() => window.sent)).toEqual(inputs.slice(0, index + 1));
    await expect(page.getByRole('dialog')).toHaveCount(0);
  }
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
  expect(await dashboard.evaluate(() => SecretShieldStats.read())).toEqual({ detected: 0, maskedPrompts: 0, unmaskedPrompts: 0 });
});

for (const failure of ['INVALID_REQUIRED', 'COMPARISON_LIMIT']) test(`${failure}: the worker fails closed without partial review and a fresh valid scan can retry`, async () => {
  const { page, editor } = await chat();
  const input = `${failure}\n` + (failure === 'INVALID_REQUIRED' ? draft : 'SERVICE\n' + Array(1001).fill('credential=ABC123').join('\n'));
  await editor.fill(input);
  await editor.press('Enter');
  await expect(page.locator('#secret-shield-notice')).toBeVisible();
  await expect(editor).toHaveValue(input);
  expect(await page.evaluate(() => window.sent)).toEqual([]);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
  expect(await dashboard.evaluate(() => SecretShieldStats.read())).toEqual({ detected: 0, maskedPrompts: 0, unmaskedPrompts: 0 });
  await editor.fill(draft);
  await editor.press('Enter');
  await expect(page.getByRole('dialog').locator('.review-values code')).toHaveText(['ABC123']);
});
