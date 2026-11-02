(() => {
  'use strict';
  // Restrict matching to chat composers and send controls.
  const adapters = {
    'chatgpt.com': {
      name: 'ChatGPT',
      editors: '#prompt-textarea, textarea[data-id="root"], [contenteditable="true"][role="textbox"][data-composer-markdown]',
      send: 'button[data-testid="send-button"], button[aria-label="Send prompt"], button[aria-label="Send message"], button[aria-label="Send"]',
    },
    'claude.ai': {
      name: 'Claude',
      editors: '[contenteditable="true"][data-testid="chat-input"], [contenteditable="true"][data-placeholder], fieldset [contenteditable="true"].ProseMirror, [contenteditable="true"].tiptap',
      send: 'button[aria-label="Send message"], button[data-testid="send-button"]',
    },
    'gemini.google.com': {
      name: 'Gemini',
      editors: 'rich-textarea .ql-editor[contenteditable="true"][role="textbox"]',
      send: 'button[aria-label="Send message"], button[aria-label="Send"], input-container button:has(mat-icon[fonticon="arrow_upward"])',
    },
    'chat.deepseek.com': {
      name: 'DeepSeek',
      editors: 'textarea#chat-input, textarea[placeholder*="DeepSeek" i]',
      disabled: '.ds-button--disabled, .ds-icon-button--disabled',
      send: 'button[aria-label="Send message"], button[aria-label="Send"], [role="button"][aria-label="Send message"], [role="button"][aria-label="Send"], [role="button"]:has(svg[viewBox="0 0 14 16"]), [role="button"].ds-button--primary.ds-button--circle:has(svg path[d^="M8.3125 0.980206"])',
    },
    'grok.com': {
      name: 'Grok',
      editors: '.query-bar-editor[contenteditable="true"], textarea[aria-label="Ask Grok anything"]',
      send: 'button[data-testid="chat-submit"], form:has(.query-bar-editor) button[aria-label="Submit"]',
    },
    'www.meta.ai': {
      name: 'Meta AI',
      editors: '[contenteditable="true"][role="textbox"][data-testid="composer-input"], textarea[data-testid="composer-input"], input[aria-label="Ask Meta AI"], textarea[aria-label="Ask Meta AI"], textarea[placeholder="Ask Meta AI anything..."], [contenteditable="true"][role="textbox"][aria-label="Ask Meta AI"]',
      send: 'button[data-testid="composer-send-button"], button[aria-label="Send"], button[aria-label="Send message"], [role="button"][aria-label="Send"], [role="button"][aria-label="Send message"]',
    },
    'copilot.microsoft.com': {
      name: 'Microsoft Copilot',
      editors: 'textarea#userInput, #m365-chat-editor-target-element[contenteditable="true"], [contenteditable="true"][role="textbox"][aria-label="Message Copilot"]',
      send: 'button[data-testid="submit-button"], button[data-testid="chat-input-send-button"], button[aria-label="Submit message"], button[aria-label="Send message"], button[aria-label="Send"], button[aria-label="Submit"]',
    },
    'www.perplexity.ai': {
      name: 'Perplexity',
      editors: '#ask-input[contenteditable="true"], textarea#ask-input',
      send: 'button[aria-label="Submit"], button[aria-label="Send"], button[data-testid="submit-button"]',
    },
    'chat.mistral.ai': {
      name: 'Mistral',
      editors: '[data-chat-input-bar] .ProseMirror[contenteditable="true"], form .ProseMirror[contenteditable="true"][data-placeholder]',
      send: 'button[aria-label="Send question"], button[aria-label="Send message"], button[aria-label="Send"], form:has([data-chat-input-bar]) button[type="submit"]:not([aria-label*="Stop" i]):not([aria-label*="Cancel" i])',
    },
  };
  adapters['chat.openai.com'] = adapters['chatgpt.com'];
  adapters['meta.ai'] = adapters['www.meta.ai'];
  for (const host of ['copilot.com', 'copilot.cloud.microsoft', 'm365.cloud.microsoft']) adapters[host] = adapters['copilot.microsoft.com'];
  adapters['perplexity.ai'] = adapters['www.perplexity.ai'];
  const editInputs = 'textarea, [contenteditable="true"][role="textbox"], [contenteditable="true"].ProseMirror, [contenteditable="true"].ql-editor, [contenteditable="true"][data-lexical-editor="true"]';
  const controls = 'button, [role="button"], input[type="submit"]';
  const editAction = /^(?:send(?: message)?|resend|submit(?: message)?|save(?: changes| (?:and|&) (?:send|submit))?|update(?: message)?)$/i;
  const cancelAction = /^(?:cancel(?: edit(?:ing)?| changes)?|discard(?: changes)?)$/i;
  function getAdapter(hostname) { return adapters[hostname] ?? null; }
  function isVisible(element) {
    return element.isConnected && element.getClientRects().length > 0 &&
      !element.closest('[hidden], [aria-hidden="true"]') && getComputedStyle(element).visibility === 'visible';
  }
  function controlLabel(control) {
    return (control.getAttribute('aria-label') || control.innerText || control.value || '').trim().replace(/\s+/g, ' ');
  }
  function editScope(element) {
    // Cancel identifies a local edit panel even while its Save/Send control remounts.
    for (let scope = element.parentElement; scope && scope !== document.body; scope = scope.parentElement) {
      const buttons = [...scope.querySelectorAll(controls)].filter(isVisible);
      if (buttons.some(button => cancelAction.test(controlLabel(button))) && scope.querySelector(editInputs)) return scope;
      if (scope instanceof HTMLFormElement) break;
    }
    return null;
  }
  function getEditors(adapter, scope = document) {
    const candidates = [...scope.querySelectorAll(`${adapter.editors}, ${editInputs}`)];
    return candidates.filter(editor => isVisible(editor) && (editor.matches(adapter.editors) ||
      !editor.disabled && !editor.readOnly && editScope(editor)));
  }
  function getSendControl(adapter, target) {
    const button = target instanceof Element ? target.closest(`${adapter.send}, ${controls}`) : null;
    return button && (button.matches(adapter.send) || editAction.test(controlLabel(button)) && editScope(button)) ? button : null;
  }
  function getSendButtons(adapter, scope = document) {
    return [...document.querySelectorAll(`${adapter.send}, ${controls}`)].filter(button =>
      isVisible(button) && (scope.contains(button) || scope instanceof HTMLFormElement && button.form === scope) &&
      getSendControl(adapter, button) === button);
  }
  function submissionScope(adapter, target) {
    // A message edit and the bottom composer can both remain open.
    const form = target instanceof HTMLFormElement ? target : target.form ?? target.closest('form');
    if (form) return form;
    const editor = getEditors(adapter).includes(target);
    for (let scope = target.parentElement; scope; scope = scope.parentElement) {
      if (editor ? getSendButtons(adapter, scope).length : getEditors(adapter, scope).length) return scope;
    }
    return document;
  }
  function readEditor(editor) {
    return editor instanceof HTMLTextAreaElement || editor instanceof HTMLInputElement ? editor.value : editor.innerText;
  }
  function editorPoint(editor, text, offset) {
    const walker = document.createTreeWalker(editor, NodeFilter.SHOW_TEXT);
    let cursor = 0;
    for (let node; node = walker.nextNode();) {
      const range = document.createRange();
      range.selectNodeContents(node);
      if (!node.data || !range.getClientRects().length || getComputedStyle(node.parentElement).visibility !== 'visible') continue;
      const start = text.indexOf(node.data, cursor);
      if (start < 0 && !node.data.trim()) continue;
      if (start < 0 || /\S/.test(text.slice(cursor, start))) throw new Error('Editor text could not be mapped');
      const end = start + node.length;
      if (offset >= start && offset <= end) return { node, offset: offset - start };
      cursor = end;
    }
    throw new Error('Editor text could not be mapped');
  }
  async function writeEditor(editor, text, findings, scope = document) {
    if (editor instanceof HTMLTextAreaElement || editor instanceof HTMLInputElement) {
      const prototype = editor instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(prototype, 'value').set.call(editor, text);
    } else {
      // Use editing transactions so rich-editor state stays in sync.
      editor.focus();
      const selection = window.getSelection();
      if (findings?.length) {
        // Replace values from the end so earlier offsets and paragraph boundaries stay intact.
        let current = readEditor(editor);
        for (const finding of [...findings].reverse()) {
          const start = editorPoint(editor, current, finding.start);
          const end = editorPoint(editor, current, finding.end);
          const range = document.createRange();
          range.setStart(start.node, start.offset);
          range.setEnd(end.node, end.offset);
          selection.removeAllRanges();
          selection.addRange(range);
          if (start.node !== end.node) {
            // Let rich editors synchronize cross-node selections before editing.
            await new Promise(resolve => setTimeout(resolve, 0));
            const selected = selection.rangeCount === 1 ? selection.getRangeAt(0) : null;
            if (readEditor(editor) !== current || selected?.startContainer !== start.node || selected.startOffset !== start.offset ||
                selected.endContainer !== end.node || selected.endOffset !== end.offset) throw new Error('Editor update failed');
          }
          const expected = current.slice(0, finding.start) + SecretShieldCore.MASK + current.slice(finding.end);
          // Give rich editors their controlled replacement before native DOM editing.
          const nativeEdit = editor.dispatchEvent(new InputEvent('beforeinput', {
            bubbles: true, cancelable: true, inputType: 'insertText', data: SecretShieldCore.MASK,
          }));
          if (nativeEdit && !document.execCommand('insertText', false, SecretShieldCore.MASK)) throw new Error('Editor update failed');
          // Let batched editor state commit before replacing another value in the same text node.
          await Promise.resolve();
          if (!editor.isConnected) {
            const replacements = getEditors(getAdapter(location.hostname), scope);
            if (replacements.length !== 1 || readEditor(replacements[0]) !== expected) throw new Error('Editor update failed');
            editor = replacements[0];
            editor.focus();
          }
          // Chromium may add a BR when replacing across blocks. Remove only
          // that exact extra newline through an editing transaction.
          const at = finding.start + SecretShieldCore.MASK.length;
          const caret = selection.anchorNode;
          const extraBreak = caret?.nodeType === Node.TEXT_NODE && selection.anchorOffset === caret.length ? caret.nextSibling : null;
          if (current.slice(finding.start, finding.end).includes('\n') && expected[at] === '\n' &&
              extraBreak instanceof HTMLBRElement && editor.contains(extraBreak) &&
              readEditor(editor) === expected.slice(0, at) + '\n' + expected.slice(at)) {
            const cleanup = document.createRange();
            cleanup.selectNode(extraBreak);
            selection.removeAllRanges();
            selection.addRange(cleanup);
            if (!document.execCommand('insertText', false, '\n')) throw new Error('Editor update failed');
            await Promise.resolve();
          }
          if (readEditor(editor) !== expected) throw new Error('Editor update failed');
          current = expected;
        }
        if (current !== text) throw new Error('Editor update failed');
      } else {
        const range = document.createRange();
        range.selectNodeContents(editor);
        selection.removeAllRanges();
        selection.addRange(range);
        if (!document.execCommand('insertText', false, text)) editor.textContent = text;
      }
    }
    editor.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertReplacementText' }));
    if (readEditor(editor) !== text) throw new Error('Editor update failed');
  }
  globalThis.SecretShieldAdapters = Object.freeze({ getAdapter, getEditors, getSendControl, getSendButtons, submissionScope, isVisible, readEditor, writeEditor });
})();
