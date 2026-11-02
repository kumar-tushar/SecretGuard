import { test, expect, chromium } from '@playwright/test';
import path from 'node:path';
import { providerKey } from '../fixtures/gitleaks-credentials.mjs';

const providers = [
  { host: 'chatgpt.com', editor: '<div contenteditable="true" role="textbox" data-composer-markdown></div>', send: 'data-testid="send-button"', action: 'Send', rich: true },
  { host: 'claude.ai', editor: '<div contenteditable="true" class="tiptap"></div>', send: 'aria-label="Send message"', action: 'Save' },
  { host: 'gemini.google.com', editor: '<rich-textarea><div contenteditable="true" role="textbox" class="ql-editor"></div></rich-textarea>', send: 'aria-label="Send message"', action: 'Update', rich: true },
  { host: 'chat.deepseek.com', editor: '<textarea placeholder="Message DeepSeek"></textarea>', send: 'aria-label="Send"', action: 'Send' },
  { host: 'grok.com', editor: '<div contenteditable="true" class="query-bar-editor"></div>', send: 'data-testid="chat-submit"', action: 'Save changes' },
  { host: 'www.meta.ai', editor: '<div contenteditable="true" role="textbox" data-testid="composer-input"></div>', send: 'data-testid="composer-send-button"', action: 'Save', rich: true },
  { host: 'copilot.cloud.microsoft', editor: '<textarea id="userInput"></textarea>', send: 'aria-label="Send"', action: 'Save and submit' },
  { host: 'www.perplexity.ai', editor: '<div id="ask-input" contenteditable="true"></div>', send: 'aria-label="Submit"', action: 'Save', rich: true },
  { host: 'chat.mistral.ai', editor: '<div data-chat-input-bar><div class="ProseMirror" contenteditable="true"></div></div>', send: 'aria-label="Send question"', action: 'Send', rich: true },
];
let context, worker;
const review = page => page.getByRole('dialog');
const read = editor => editor.evaluate(element => element.value ?? element.innerText);

function fixture(provider, formless) {
  const tag = formless ? 'section' : 'form';
  const edit = provider.rich ? '<div contenteditable="true" role="textbox" aria-label="Edit message"' +
    (provider.host === 'chatgpt.com' ? ' data-composer-markdown' : '') + '></div>' : '<textarea aria-label="Edit message"></textarea>';
  return `<!doctype html><html><head><style>[contenteditable]{min-height:60px;white-space:pre-wrap}</style></head><body>
    <form id="search"><textarea aria-label="Search conversations"></textarea><button>Search</button></form>
    <${tag} id="edited">${edit}<button type="button" class="cancel">Cancel</button><button type="${formless ? 'button' : 'submit'}" class="send">${provider.action}</button></${tag}>
    <${tag} id="compose">${provider.editor}<button type="${formless ? 'button' : 'submit'}" class="send" ${provider.send}>Send</button></${tag}>
    <script>
    window.options={};window.current={};window.submitted=[];window.cancelled=0;window.searches=0;
    const read=editor=>editor.value??editor.innerText;
    function bind(editor,scope){
      editor.addEventListener('input',()=>{
        window.current[scope.id]=read(editor);
        if(window.options.remount&&scope.id==='edited'){
          window.options.remount=false;
          queueMicrotask(()=>{const replacement=editor.cloneNode(true);editor.replaceWith(replacement);bind(replacement,scope);});
        }
      });
      editor.addEventListener('keydown',event=>{if(event.key==='Enter'&&!event.shiftKey&&!window.options.newline){event.preventDefault();scope.querySelector('.send').click();}});
    }
    for(const scope of document.querySelectorAll('#edited,#compose')){
      bind(scope.querySelector('textarea,[contenteditable]'),scope);
      const send=()=>{const entry={editor:scope.id,text:window.current[scope.id]};window.submitted.push(entry);fetch('/test-submit',{method:'POST',body:JSON.stringify(entry)});};
      scope.querySelector('.send').addEventListener('click',event=>{
        if(scope.tagName!=='FORM'){event.preventDefault();send();}
        else if(window.options.deferred){event.preventDefault();setTimeout(()=>{scope.requestSubmit();scope.requestSubmit();},20);}
      });
      scope.addEventListener('submit',event=>{event.preventDefault();send();});
    }
    document.querySelector('.cancel').addEventListener('click',()=>window.cancelled++);
    document.querySelector('#search').addEventListener('submit',event=>{event.preventDefault();window.searches++;});
    </script></body></html>`;
}

test.beforeAll(async () => {
  const extension = path.resolve('dist');
  context = await chromium.launchPersistentContext('', { channel: 'chromium', headless: true, reducedMotion: 'reduce',
    args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension] });
  worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
  await context.route(/^https:\/\//, route => {
    if (route.request().method() === 'POST') return route.fulfill({ body: 'ok' });
    const url = new URL(route.request().url()), provider = providers.find(item => item.host === url.hostname);
    if (!provider) return route.abort();
    return route.fulfill({ contentType: 'text/html', body: fixture(provider, url.searchParams.has('formless')) });
  });
});
test.afterEach(async () => {
  for (const page of context.pages()) await page.close();
  await worker.evaluate(async () => { await pending; await SecretShieldHistory.perform('clear'); await chrome.storage.local.clear(); });
});
test.afterAll(async () => { await context?.close(); });

async function chat(provider, formless = false) {
  await worker.evaluate(() => chrome.storage.local.set({ policy: { sensitiveNames: ['dataset_key'] } }));
  const page = await context.newPage(), requests = [], errors = [];
  page.on('request', request => { if (request.method() === 'POST') requests.push(JSON.parse(request.postData())); });
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('https://' + provider.host + '/?'+ (formless ? 'formless' : ''));
  const id = await worker.evaluate(async url => (await chrome.tabs.query({ url }))[0].id, page.url());
  await expect.poll(() => worker.evaluate(async id => {
    try { return (await chrome.tabs.sendMessage(id, { type: 'coverage' })).ready; } catch { return false; }
  }, id)).toBe(true);
  return { page, id, requests, errors, editor: page.locator('#edited').locator('textarea,[contenteditable]'), composer: page.locator('#compose').locator('textarea,[contenteditable]') };
}

async function attempt(state, gesture) {
  if (gesture === 'Enter') await state.editor.press('Enter');
  else if (gesture === 'submit') await state.page.locator('#edited').evaluate(form => form.requestSubmit());
  else await state.page.locator('#edited .send').click();
}

for (const provider of providers) {
  for (const formless of [false, true]) test(provider.host + ': clean edit and bottom composer send independently in ' + (formless ? 'panels' : 'forms'), async () => {
    const state = await chat(provider, formless);
    const draft = 'dataset_key=bottom-draft-must-stay';
    await state.composer.fill(draft);
    await state.editor.fill('Explain binary search trees.');
    await attempt(state, 'button');
    await expect.poll(() => state.requests).toEqual([{ editor: 'edited', text: 'Explain binary search trees.' }]);
    await expect(review(state.page)).toBeHidden();
    expect(await read(state.composer)).toBe(draft);
    await state.page.locator('#compose .send').click();
    await expect(review(state.page).locator('.review-values code')).toHaveText(['bottom-draft-must-stay']);
    await review(state.page).getByRole('button', { name: 'Mask', exact: true }).click();
    await expect.poll(() => state.requests).toEqual([{ editor: 'edited', text: 'Explain binary search trees.' }, { editor: 'compose', text: 'dataset_key=xxxxxxxxxx' }]);
    expect(await read(state.editor)).toBe('Explain binary search trees.');
    expect(state.errors).toEqual([]);
  });

  for (const formless of [false, true]) for (const action of ['Edit', 'Send', 'Mask']) test(provider.host + ': edited secrets retain ' + action + ' in ' + (formless ? 'panels' : 'forms'), async () => {
    const state = await chat(provider, formless);
    const bottom = 'dataset_key=bottom-secret-is-unrelated';
    await state.composer.fill(bottom);
    for (const gesture of formless ? ['button', 'Enter'] : ['button', 'Enter', 'submit']) {
      const prefix = 'New credential (' + gesture + '): ', original = prefix + providerKey;
      await state.editor.fill(original);
      await attempt(state, gesture);
      await expect(review(state.page).locator('.review-values code')).toHaveText([providerKey]);
      const before = state.requests.length;
      await review(state.page).getByRole('button', { name: action, exact: true }).click();
      await expect(review(state.page)).toBeHidden();
      if (action === 'Edit') {
        expect(state.requests).toHaveLength(before);
        expect(await read(state.editor)).toBe(original);
        await expect(state.editor).toBeFocused();
      } else {
        await expect.poll(() => state.requests.length).toBe(before + 1);
        expect(state.requests[before]).toEqual({ editor: 'edited', text: action === 'Send' ? original : prefix + 'xxxxxxxxxx' });
      }
      expect(await read(state.composer)).toBe(bottom);
    }
    expect(state.errors).toEqual([]);
  });

  for (const action of ['Send', 'Mask']) test(provider.host + ': edit ' + action + ' waits for its own Save control to return', async () => {
    const state = await chat(provider);
    await state.composer.fill('dataset_key=bottom-private-value');
    await state.editor.fill('dataset_key=edited-private-value');
    await attempt(state, 'button');
    await expect(review(state.page)).toBeVisible();
    await state.page.evaluate(action => {
      const scope = document.querySelector('#edited');
      const remove = () => {
        const button = scope.querySelector('.send');
        button.remove();
        setTimeout(() => scope.append(button), 200);
      };
      if (action === 'Send') remove();
      else scope.querySelector('textarea,[contenteditable]').addEventListener('input', remove, { once: true });
    }, action);
    await review(state.page).getByRole('button', { name: action, exact: true }).click();
    await expect.poll(() => state.requests).toEqual([{ editor: 'edited', text: action === 'Send' ? 'dataset_key=edited-private-value' : 'dataset_key=xxxxxxxxxx' }]);
    expect(await read(state.composer)).toBe('dataset_key=bottom-private-value');
    expect(state.errors).toEqual([]);
  });

  test(provider.host + ': strict edit protection, short custom values and Cancel remain active', async () => {
    const state = await chat(provider);
    await worker.evaluate(() => chrome.storage.local.set({ policy: { mode: 'block', sensitiveNames: ['dataset_key'] } }));
    await state.editor.fill('dataset_key=12');
    await attempt(state, 'button');
    await expect(review(state.page).locator('.review-values code')).toHaveText(['12']);
    await expect(review(state.page).getByRole('button', { name: 'Send', exact: true })).toHaveCount(0);
    await review(state.page).getByRole('button', { name: 'Mask', exact: true }).click();
    await expect.poll(() => state.requests).toEqual([{ editor: 'edited', text: 'dataset_key=xxxxxxxxxx' }]);
    await state.page.locator('#edited .cancel').click();
    expect(await state.page.evaluate(() => window.cancelled)).toBe(1);
    await state.page.locator('#search textarea').fill('dataset_key=search-must-not-be-scanned');
    await state.page.locator('#search button').click();
    expect(await state.page.evaluate(() => window.searches)).toBe(1);
    await expect(review(state.page)).toBeHidden();
    expect(state.errors).toEqual([]);
  });

  test(provider.host + ': duplicate editors inside one edit form still block sending', async () => {
    const state = await chat(provider);
    await state.editor.fill('Explain binary search trees.');
    await state.editor.evaluate(editor => editor.after(editor.cloneNode(true)));
    await attempt(state, 'button');
    await expect(state.page.locator('#secret-shield-notice')).toBeVisible();
    expect(state.requests).toEqual([]);
    expect(state.errors).toEqual([]);
  });
}

for (const replacement of ['same', 'changed', 'another-form']) test('edit Mask handles a ' + replacement + ' framework replacement without switching drafts', async () => {
  const state = await chat(providers[0]);
  await state.composer.fill('dataset_key=bottom-private-value');
  await state.editor.fill('dataset_key="first\nsecond"');
  await attempt(state, 'button');
  await expect(review(state.page)).toBeVisible();
  await state.page.evaluate(replacement => {
    window.options.remount = true;
    if (replacement !== 'same') document.querySelector('#edited [contenteditable]').addEventListener('input', () => queueMicrotask(() => {
      const editor = document.querySelector('#edited [contenteditable]');
      if (replacement === 'changed') editor.textContent = 'dataset_key=changed-secret';
      else { editor.remove(); document.querySelector('#compose').append(editor); }
    }), { once: true });
  }, replacement);
  await review(state.page).getByRole('button', { name: 'Mask', exact: true }).click();
  if (replacement === 'same') await expect.poll(() => state.requests).toEqual([{ editor: 'edited', text: 'dataset_key="xxxxxxxxxx"' }]);
  else {
    await expect(state.page.locator('#secret-shield-notice')).toBeVisible();
    expect(state.requests).toEqual([]);
  }
  expect(await read(state.composer.first())).toBe('dataset_key=bottom-private-value');
  expect(state.errors).toEqual([]);
});

test('an approved edit cannot approve the separate composer and deferred submits run once', async () => {
  const state = await chat(providers[0]);
  await state.composer.fill('dataset_key=bottom-private-value');
  await state.editor.fill('dataset_key=edited-private-value');
  await attempt(state, 'button');
  await expect(review(state.page)).toBeVisible();
  await state.page.evaluate(() => { window.options.deferred = true; });
  await review(state.page).getByRole('button', { name: 'Send', exact: true }).click();
  await expect.poll(() => state.requests).toEqual([{ editor: 'edited', text: 'dataset_key=edited-private-value' }]);
  await state.page.locator('#compose').evaluate(form => form.requestSubmit());
  await expect(review(state.page).locator('.review-values code')).toHaveText(['bottom-private-value']);
  expect(state.requests).toHaveLength(1);
  expect(state.errors).toEqual([]);
});

test('alternate edit textareas retain native Enter newlines and review only when Save is selected', async () => {
  const state = await chat(providers[1]);
  await state.page.evaluate(() => { window.options.newline = true; });
  await state.editor.fill('dataset_key=edited-private-value');
  await state.editor.press('End');
  await state.editor.press('Enter');
  await expect(state.editor).toHaveValue('dataset_key=edited-private-value\n');
  await expect(review(state.page)).toBeHidden();
  expect(state.requests).toEqual([]);
  await attempt(state, 'button');
  await expect(review(state.page).locator('.review-values code')).toHaveText(['edited-private-value']);
  expect(state.requests).toEqual([]);
  expect(state.errors).toEqual([]);
});
