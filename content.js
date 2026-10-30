/**
 * IOCulus — Content Script
 * Handles IOC extraction from page text and relays network inspection requests.
 */

(function () {
  'use strict';

  // ─── Message Handler ────────────────────────────────────────────────────────

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'get-page-text') {
      sendResponse({ text: document.body ? document.body.innerText : '' });
      return false;
    }
    if (msg.action === 'highlight-ioc') {
      highlightText(msg.value);
      sendResponse({ ok: true });
      return false;
    }
    return false;
  });

  // ─── Text Highlighting ──────────────────────────────────────────────────────

  function highlightText(searchTerm) {
    // Simple: use window.find for a quick highlight
    window.getSelection()?.removeAllRanges();
    if (window.find) {
      window.find(searchTerm, false, false, true, false, false, false);
    }
  }

})();
