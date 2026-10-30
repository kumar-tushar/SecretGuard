import { test, expect, chromium } from '@playwright/test';
import { cp, mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';

const providers = [
  ['chatgpt.com', '<textarea id="prompt-textarea"></textarea>'],
  ['claude.ai', '<div contenteditable="true" data-testid="chat-input"></div>'],
  ['gemini.google.com', '<rich-textarea><div class="ql-editor" role="textbox" contenteditable="true"></div></rich-textarea>'],
  ['chat.deepseek.com', '<textarea placeholder="Message DeepSeek"></textarea>'],
  ['grok.com', '<div class="query-bar-editor" role="combobox" contenteditable="true"></div>'],
  ['www.meta.ai', '<textarea data-testid="composer-input"></textarea>'],
  ['copilot.microsoft.com', '<textarea id="userInput"></textarea>'],
  ['www.perplexity.ai', '<textarea id="ask-input"></textarea>'],
  ['chat.mistral.ai', '<div data-chat-input-bar><div class="ProseMirror" contenteditable="true"></div></div>'],
];
let context, background, dashboard, directory;
test.beforeAll(async () => {
  directory = await mkdtemp('/tmp/ckretguard-scan-browser-');
  await cp(path.resolve('dist'), directory, { recursive: true });
  // Only this private fixture stalls/crashes workers. Production detection is unchanged.
  await writeFile(path.join(directory, 'scan-worker.js'), await readFile(path.join(directory, 'scan-worker.js'), 'utf8') + `
    const actualScan = self.onmessage;
    self.onmessage = event => {
      const text = event.data.text;
      if (text.startsWith('STALL\\n') || text.startsWith('MASK_TIMEOUT\\n') && text.includes('xxxxxxxxxx')) { while (true) {} }
      if (text.startsWith('CRASH\\n')) throw new Error('fixture crash');
      if (text.startsWith('MALFORMED\\n')) { postMessage({ok:true,result:{text:'wrong',count:0,findings:[]}}); return; }
      actualScan(event);
    };`);
  context = await chromium.launchPersistentContext('', { channel: 'chromium', headless: true, reducedMotion: 'reduce',
    args: ['--disable-extensions-except=' + directory, '--load-extension=' + directory] });
  background = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
  const id = new URL(background.url()).hostname;
  await context.route(url => providers.some(([host]) => url.hostname === host), route => {
    const host = new URL(route.request().url()).hostname;
    const editor = providers.find(([name]) => name === host)[1];
    const label = host === 'www.perplexity.ai' ? 'Submit' : host === 'chat.mistral.ai' ? 'Send question' : 'Send message';
    const testId = host === 'grok.com' ? 'chat-submit' : 'send-button';
    return route.fulfill({ contentType: 'text/html', headers: { 'Content-Security-Policy': "default-src 'self'; worker-src 'none'; frame-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'" },
      body: `<!doctype html><html><head><title>Worker fixture</title><style>[contenteditable]{min-height:80px;white-space:pre-wrap}</style></head><body><form>${editor}
      <button type="submit" data-testid="${testId}" aria-label="${label}">Send</button></form><script>
      window.sent=[];const editor=document.querySelector('textarea,[contenteditable]');
      const send=()=>window.sent.push(editor.value??editor.innerText);
      editor.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send();}});
      document.querySelector('form').addEventListener('submit',e=>{e.preventDefault();send();});
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
  const id = await background.evaluate(async url => (await chrome.tabs.query({ url }))[0].id, page.url());
  await expect.poll(() => background.evaluate(async id => (await chrome.tabs.sendMessage(id, { type: 'coverage' })).ready, id)).toBe(true);
  return { page, id, editor: page.locator('textarea,[contenteditable]') };
}
const frames = page => page.frames().filter(frame => frame.url().endsWith('/scan-host.html'));
async function stalled(state, text = 'STALL\nRetain this complete draft.') {
  await state.editor.fill(text);
  const started = state.page.waitForEvent('worker');
  await state.editor.press('Enter');
  const worker = await started;
  await expect.poll(() => frames(state.page).length).toBe(1);
  return worker;
}
async function emptyHistory() {
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
  expect(await dashboard.evaluate(() => SecretShieldStats.read())).toEqual({ detected: 0, maskedPrompts: 0, unmaskedPrompts: 0 });
}

for (const [host] of providers) test(`${host}: local workers scan and mask despite restrictive page CSP`, async () => {
  const state = await chat(host);
  await state.editor.fill('client_id=demo-client-123');
  await state.editor.press('Enter');
  const review = state.page.getByRole('dialog');
  await expect(review.locator('.review-values code')).toHaveText(['demo-client-123']);
  await review.getByRole('button', { name: 'Mask', exact: true }).click();
  await expect.poll(() => state.page.evaluate(() => window.sent)).toEqual(['client_id=xxxxxxxxxx']);
  await expect.poll(() => frames(state.page).length).toBe(0);
  expect(state.page.workers()).toHaveLength(0);
});

for (const [host] of providers) test(`${host}: encoding tags survive the private worker channel without changing review or Mask`, async () => {
  const state = await chat(host), value = 'demo-client-123';
  const hex = Buffer.from(`client_id=${value}`).toString('hex');
  const percent = [...Buffer.from(hex)].map(byte => '%' + byte.toString(16).padStart(2, '0')).join('');
  const encoded = Buffer.from(percent).toString('base64'), input = `😀 ${encoded}\nKeep this.`;
  const [{ result }] = await background.evaluate(({ id, text }) => chrome.scripting.executeScript({
    target: { tabId: id }, func: async text => SecretShieldScanner.redact(text), args: [text],
  }), { id: state.id, text: input });
  expect(result).toEqual({ text: '😀 xxxxxxxxxx\nKeep this.', count: 1, findings: [{ start: 3, end: 3 + encoded.length,
    type: 'client-id', tags: ['decoded:percent', 'decoded:hex', 'decoded:base64', 'decode-depth:3'] }] });
  await expect.poll(() => frames(state.page).length).toBe(0);
  await emptyHistory();
  await state.editor.fill(input);
  await state.editor.press('Enter');
  const review = state.page.getByRole('dialog');
  await expect(review.locator('.review-values code')).toHaveText([encoded]);
  await expect(review.getByRole('button')).toHaveText(['Send', 'Edit', 'Mask']);
  await review.getByRole('button', { name: 'Mask', exact: true }).click();
  await expect.poll(() => state.page.evaluate(() => window.sent)).toEqual(['😀 xxxxxxxxxx\nKeep this.']);
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
  expect(await dashboard.evaluate(() => SecretShieldStats.read())).toEqual({ detected: 1, maskedPrompts: 1, unmaskedPrompts: 0 });
});

test('a hung worker times out while the chat remains responsive and retry uses a fresh worker', async () => {
  const state = await chat();
  await state.page.evaluate(() => { window.ticks = 0; setInterval(() => window.ticks++, 20); });
  await stalled(state);
  await expect.poll(() => state.page.evaluate(() => window.ticks)).toBeGreaterThan(3);
  await expect(state.page.locator('#secret-shield-notice')).toBeVisible({ timeout: 7000 });
  await expect.poll(() => frames(state.page).length).toBe(0);
  expect(state.page.workers()).toHaveLength(0);
  await expect(state.editor).toHaveValue('STALL\nRetain this complete draft.');
  expect(await state.page.evaluate(() => window.sent)).toEqual([]);
  await emptyHistory();
  await state.editor.fill('Fresh ordinary prompt.'); await state.editor.press('Enter');
  await expect.poll(() => state.page.evaluate(() => window.sent)).toEqual(['Fresh ordinary prompt.']);
});

for (const change of ['input', 'policy', 'reload']) test(`changing ${change} cancels a running worker and discards the old result`, async () => {
  const state = await chat('claude.ai');
  await stalled(state);
  if (change === 'input') await state.editor.fill('A replacement prompt.');
  if (change === 'policy') await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'set', key: 'protectClientIds', value: false }));
  if (change === 'reload') await background.evaluate(id => chrome.scripting.executeScript({ target: { tabId: id }, files: chrome.runtime.getManifest().content_scripts[0].js }), state.id);
  await expect.poll(() => frames(state.page).length).toBe(0);
  expect(state.page.workers()).toHaveLength(0);
  await expect(state.page.getByRole('dialog')).toHaveCount(0);
  expect(await state.page.evaluate(() => window.sent)).toEqual([]);
  await emptyHistory();
  await state.editor.fill('client_secret=N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8'); await state.editor.press('Enter');
  await expect(state.page.getByRole('dialog')).toBeVisible();
});

for (const prefix of ['CRASH', 'MALFORMED']) test(`${prefix} worker responses block sending and leave the draft intact`, async () => {
  const state = await chat(), text = prefix + '\nPreserve this text.';
  await state.editor.fill(text); await state.editor.press('Enter');
  await expect(state.page.locator('#secret-shield-notice')).toBeVisible();
  await expect(state.editor).toHaveValue(text);
  expect(await state.page.evaluate(() => window.sent)).toEqual([]);
  await expect.poll(() => frames(state.page).length).toBe(0);
  await emptyHistory();
});

test('a timeout during Mask verification leaves the original draft unchanged and records no send', async () => {
  const state = await chat(), text = 'MASK_TIMEOUT\nclient_id=demo-client-123';
  await state.editor.fill(text); await state.editor.press('Enter');
  const review = state.page.getByRole('dialog');
  await expect(review).toBeVisible();
  await review.getByRole('button', { name: 'Mask', exact: true }).click();
  await expect(state.page.locator('#secret-shield-notice')).toBeVisible({ timeout: 7000 });
  await expect(state.editor).toHaveValue(text);
  expect(await state.page.evaluate(() => window.sent)).toEqual([]);
  await expect.poll(() => frames(state.page).length).toBe(0);
  expect(await dashboard.evaluate(() => SecretShieldStats.read())).toEqual({ detected: 1, maskedPrompts: 0, unmaskedPrompts: 0 });
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
});

test('page messages cannot forge a clean result or revive a cancelled scan', async () => {
  const state = await chat();
  await stalled(state);
  await state.page.evaluate(() => {
    for (let i = 0; i < 10; i++) window.postMessage({ ok: true, result: { text: '', count: 0, findings: [] } }, '*');
  });
  expect(await state.page.evaluate(() => window.sent)).toEqual([]);
  await expect(state.page.getByRole('dialog')).toHaveCount(0);
  await state.editor.fill('A fresh draft.');
  await expect.poll(() => frames(state.page).length).toBe(0);
  await emptyHistory();
});

test('policy changes cancel pending Mask verification before any editor write', async () => {
  const state = await chat(), text = 'MASK_TIMEOUT\nclient_id=demo-client-123';
  await state.editor.fill(text); await state.editor.press('Enter');
  const review = state.page.getByRole('dialog');
  await expect(review).toBeVisible();
  const started = state.page.waitForEvent('worker');
  await review.getByRole('button', { name: 'Mask', exact: true }).click();
  await started;
  await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'set', key: 'mode', value: 'block' }));
  await expect(review).toHaveCount(0);
  await expect.poll(() => frames(state.page).length).toBe(0);
  expect(state.page.workers()).toHaveLength(0);
  await expect(state.editor).toHaveValue(text);
  expect(await state.page.evaluate(() => window.sent)).toEqual([]);
  expect(await dashboard.evaluate(() => SecretShieldHistory.request('list'))).toEqual([]);
});

test('navigation tears down the pending scan and its worker', async () => {
  const state = await chat();
  const worker = await stalled(state);
  const closed = new Promise(resolve => worker.once('close', resolve));
  await state.page.goto('https://chatgpt.com/new-chat');
  await closed;
  await expect.poll(() => frames(state.page).length).toBe(0);
  expect(state.page.workers()).toHaveLength(0);
  expect(await state.page.evaluate(() => window.sent)).toEqual([]);
  await emptyHistory();
});

test('a page restored from the browser cache keeps protection active with refreshed policy', async () => {
  const state = await chat();
  await stalled(state);
  await state.page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
  await expect.poll(() => frames(state.page).length).toBe(0);
  await state.page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
  await expect.poll(() => background.evaluate(async id => (await chrome.tabs.sendMessage(id, { type: 'coverage' })).ready, state.id)).toBe(true);
  await state.editor.fill('client_id=demo-client-123'); await state.editor.press('Enter');
  await expect(state.page.getByRole('dialog')).toBeVisible();
  expect(await state.page.evaluate(() => window.sent)).toEqual([]);
});
