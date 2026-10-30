import { test, expect, chromium } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const providers = [
  { host: 'www.perplexity.ai', attributes: 'id="ask-input"', send: 'aria-label="Submit"' },
  { host: 'www.meta.ai', attributes: 'data-testid="composer-input"', send: 'data-testid="composer-send-button"' },
  { host: 'copilot.cloud.microsoft', attributes: 'id="m365-chat-editor-target-element"', send: 'aria-label="Send"' },
];
const key = 'sk-' + 'N7q2V9m4R8s6T3x5K1p0' + 'T3BlbkFJ' + 'L2z7H4c9D6b8B9wK4s8H';
const structured = JSON.parse(await readFile(new URL('../fixtures/gitleaks-structured.json', import.meta.url), 'utf8')).examples;
const curl = JSON.parse(await readFile(new URL('../fixtures/gitleaks-curl.json', import.meta.url), 'utf8')).cases.filter(item =>
  item.ruleId === 'curl-auth-header' && item.name === 'example 2' || item.ruleId === 'curl-auth-user' && item.name === 'example 1');
const structuredValues = [key, structured['private-key'][0], structured.jwt[0], structured['private-key'][1], structured.jwt[1]];
const collaboration = JSON.parse(await readFile(new URL('../fixtures/gitleaks-collaboration.json', import.meta.url), 'utf8')).examples;
const collaborationValues = ['slack-bot-token', 'stripe-access-token', 'npm-access-token'].map(id => collaboration[id][0]);
const catalog = JSON.parse(await readFile(new URL('../fixtures/gitleaks-catalog.json', import.meta.url), 'utf8')).cases;
const extraValues = ['gitlab-pat', 'jwt-base64'].map(id => {
  const item = catalog.find(item => item.ruleId === id && item.secrets.length);
  return (item.matches ?? item.secrets)[0].replaceAll('\r', '\n');
});
const values = [...structuredValues, ...curl.flatMap(item => item.secrets), ...collaborationValues, ...extraValues];
const original = 'Please inspect these values.\n' + structuredValues.join('\n\n\n') + '\n'.repeat(10) +
  curl.map(item => item.input).join('\n'.repeat(10)) + '\n\n' + [...collaborationValues, ...extraValues].join('\n\n') + '\n\n\n\n';
const masked = text => values.reduce((output, value) => output.replaceAll(value, 'xxxxxxxxxx').replaceAll(value.replaceAll('\n', '\n\n'), 'xxxxxxxxxx'), text);
const review = page => page.getByRole('dialog');
let context, worker, dashboard;

function editorApp() {
  const root = document.querySelector('[contenteditable]'), button = document.querySelector('button');
  const editor = createEditor({ namespace: 'CkretGuardTest', onError: error => { throw error; } });
  window.current = ''; window.submitted = [];
  editor.setRootElement(root);
  // Lexical core delegates cross-node typing to the host editor's text handler.
  editor.registerCommand(CONTROLLED_TEXT_INSERTION_COMMAND, text => {
    const selection = $getSelection();
    if (!$isRangeSelection(selection) || typeof text !== 'string') return false;
    selection.insertText(text);
    return true;
  }, COMMAND_PRIORITY_EDITOR);
  editor.registerUpdateListener(({ editorState }) => {
    window.current = editorState.read(() => $getRoot().getTextContent());
  });
  window.setDraft = (text, layout) => editor.update(() => {
    $getRoot().clear();
    const lines = text.split('\n');
    if (layout === 'paragraphs') {
      for (const line of lines) $getRoot().append($createParagraphNode().append(...(line ? [$createTextNode(line)] : [])));
    } else {
      const paragraph = $createParagraphNode();
      lines.forEach((line, index) => {
        if (index) paragraph.append($createLineBreakNode());
        if (line) paragraph.append($createTextNode(line));
      });
      $getRoot().append(paragraph);
    }
  }, { discrete: true });
  button.addEventListener('click', () => {
    window.submitted.push(window.current);
    fetch('/test-submit', { method: 'POST', body: window.current });
  });
  root.addEventListener('keydown', event => {
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); button.click(); }
  });
}

test.beforeAll(async () => {
  const extension = path.resolve('dist');
  const runtime = await readFile(new URL('./Lexical.dev.js', import.meta.resolve('lexical')), 'utf8');
  context = await chromium.launchPersistentContext('', { channel: 'chromium', headless: true, reducedMotion: 'reduce',
    args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension] });
  worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
  await context.route(/^https:\/\/(?:www\.perplexity\.ai|www\.meta\.ai|copilot\.cloud\.microsoft)\//, route => {
    const request = route.request(), url = new URL(request.url());
    if (request.method() === 'POST') return route.fulfill({ body: 'ok' });
    if (url.pathname === '/test-lexical.js') return route.fulfill({ contentType: 'application/javascript', body: runtime });
    const provider = providers.find(item => item.host === url.hostname);
    return route.fulfill({ contentType: 'text/html', body: '<!doctype html><html lang="en"><head><title>Lexical regression</title><style>p{margin:0}</style></head><body>' +
      '<div ' + provider.attributes + ' contenteditable="true" role="textbox" data-lexical-editor="true" style="white-space:pre-wrap;min-height:100px"></div>' +
      '<button type="button" ' + provider.send + '>Send</button><script type="module">' +
      'import {createEditor,$createParagraphNode,$createTextNode,$createLineBreakNode,$getRoot,$getSelection,$isRangeSelection,CONTROLLED_TEXT_INSERTION_COMMAND,COMMAND_PRIORITY_EDITOR} from "/test-lexical.js";' +
      '(' + editorApp.toString() + ')();</script></body></html>' });
  });
  dashboard = await context.newPage();
  await dashboard.goto('chrome-extension://' + new URL(worker.url()).hostname + '/composer.html');
  await expect(dashboard.locator('#sensitive-names')).toBeEnabled();
});
test.afterEach(async () => {
  for (const page of context.pages()) if (page !== dashboard) await page.close();
  await dashboard.evaluate(async () => {
    await SecretShieldHistory.request('clear');
    await chrome.storage.local.remove(['policy', 'activity']);
  });
});
test.afterAll(async () => { await context?.close(); });

async function chat(provider) {
  const page = await context.newPage(), requests = [], errors = [];
  page.on('request', request => { if (request.method() === 'POST') requests.push(request.postData()); });
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('https://' + provider.host + '/');
  const id = await worker.evaluate(async url => (await chrome.tabs.query({ url }))[0].id, page.url());
  await expect.poll(() => worker.evaluate(async id => {
    try { return (await chrome.tabs.sendMessage(id, { type: 'coverage' })).ready; } catch { return false; }
  }, id)).toBe(true);
  return { page, requests, errors, editor: page.locator('[contenteditable]') };
}

for (const layout of ['paragraphs', 'linebreaks']) test('Lexical fixture supports native typing across ' + layout, async () => {
  const { page, editor } = await chat(providers[0]);
  await page.evaluate(layout => window.setDraft('Alpha\nBravo\nCharlie', layout), layout);
  await editor.focus();
  await editor.evaluate(root => {
    const range = document.createRange();
    range.selectNodeContents(root);
    const selection = getSelection();
    selection.removeAllRanges(); selection.addRange(range);
  });
  await page.keyboard.insertText('Replacement');
  await expect.poll(() => page.evaluate(() => window.current)).toBe('Replacement');
  await expect(editor).toHaveText('Replacement');
});

test('a draft changed during a multiline Mask replacement is never sent', async () => {
  const state = await chat(providers[0]);
  await state.page.evaluate(text => window.setDraft(text, 'linebreaks'), structured['private-key'][0]);
  await state.editor.press('Enter');
  await expect(review(state.page).getByRole('heading')).toHaveText('1 secret detected');
  await state.page.evaluate(() => document.addEventListener('selectionchange', () => {
    if (getSelection().toString().includes('-----BEGIN')) window.setDraft('A newer draft', 'linebreaks');
  }));
  await review(state.page).getByRole('button', { name: 'Mask', exact: true }).click();
  await expect(state.page.locator('#secret-shield-notice')).toBeVisible();
  await expect(state.editor).toHaveText('A newer draft');
  expect(await state.page.evaluate(() => window.current)).toBe('A newer draft');
  expect(state.requests).toEqual([]);
  expect(state.errors).toEqual([]);
});

for (const provider of providers) for (const layout of ['paragraphs', 'linebreaks']) {
  test(provider.host + ': real Lexical ' + layout + ' mask complete multiline custom values', async () => {
    await dashboard.evaluate(() => SecretShieldPolicy.update({ kind: 'addField', name: 'dataset_name' }));
    const state = await chat(provider);
    const draft = 'Keep this.\ndataset_name="first\n\nsecond 🔐"\n\nAfterwards.';
    await state.page.evaluate(({ draft, layout }) => window.setDraft(draft, layout), { draft, layout });
    const before = await state.editor.innerText(), model = await state.page.evaluate(() => window.current);
    await state.editor.press('Enter');
    await expect(review(state.page).getByRole('heading')).toHaveText('1 secret detected');
    await review(state.page).getByRole('button', { name: 'Mask', exact: true }).click();
    const maskValue = text => text.slice(0, text.indexOf('"') + 1) + 'xxxxxxxxxx' + text.slice(text.lastIndexOf('"'));
    await expect.poll(() => state.requests).toEqual([maskValue(model)]);
    expect(await state.page.evaluate(() => window.submitted)).toEqual([maskValue(model)]);
    expect(await state.editor.innerText()).toBe(maskValue(before));
    await expect(state.page.locator('#secret-shield-notice')).toHaveCount(0);
    expect(state.errors).toEqual([]);
  });

  for (const action of ['Edit', 'Send', 'Mask']) test(provider.host + ': real Lexical ' + layout + ' preserve credentials and cURL options through ' + action, async () => {
    const state = await chat(provider);
    await state.page.evaluate(({ original, layout }) => window.setDraft(original, layout), { original, layout });
    const before = await state.editor.innerText(), model = await state.page.evaluate(() => window.current);
    await state.editor.press('Enter');
    await expect(review(state.page).getByRole('heading')).toHaveText(`${values.length} secrets detected`);
    expect(state.requests).toEqual([]);
    await review(state.page).getByRole('button', { name: action, exact: true }).click();
    await expect(review(state.page)).toBeHidden();
    if (action === 'Edit') {
      expect(state.requests).toEqual([]); expect(await state.editor.innerText()).toBe(before);
      expect(await state.page.evaluate(() => window.current)).toBe(model);
      await expect(state.editor).toBeFocused();
    } else {
      const expected = action === 'Mask' ? masked(model) : model;
      await expect.poll(() => state.requests).toEqual([expected]);
      expect(await state.page.evaluate(() => window.submitted)).toEqual([expected]);
      expect(await state.editor.innerText()).toBe(action === 'Mask' ? masked(before) : before);
    }
    await expect(state.page.locator('#secret-shield-notice')).toHaveCount(0);
    expect(state.errors).toEqual([]);
  });
}

for (const provider of providers) test(provider.host + ': real Lexical commits each replacement before the next and sends repeated Mask clicks once', async () => {
  const state = await chat(provider);
  for (let index = 0; index < 12; index++) {
    const value = 'N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8' + index;
    const text = 'api_key=' + value + '; password=' + value + '; client_secret=' + value;
    await state.page.evaluate(text => window.setDraft(text, 'linebreaks'), text);
    const box = await state.page.locator('button').boundingBox();
    await state.page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await expect(review(state.page).getByRole('heading')).toHaveText('3 secrets detected');
    await review(state.page).getByRole('button', { name: 'Mask', exact: true }).evaluate(button => { button.click(); button.click(); });
    await expect.poll(() => state.requests.length).toBe(index + 1);
    expect(state.requests[index]).toBe('api_key=xxxxxxxxxx; password=xxxxxxxxxx; client_secret=xxxxxxxxxx');
    await expect(state.page.locator('#secret-shield-notice')).toHaveCount(0);
  }
  expect(await state.page.evaluate(() => window.submitted.length)).toBe(12);
  expect(state.errors).toEqual([]);
});
