/**
 * IOCulus — Settings page
 * Kept in an external file: MV3's CSP blocks inline scripts and onclick handlers.
 */

'use strict';

// ── Load saved keys ──────────────────────────────────────────────────────
chrome.storage.sync.get(['virusTotalKey','abuseIPDBKey','shodanKey'], (data) => {
  if (data.virusTotalKey) document.getElementById('key-vt').value         = data.virusTotalKey;
  if (data.abuseIPDBKey)  document.getElementById('key-abuseipdb').value  = data.abuseIPDBKey;
  if (data.shodanKey)     document.getElementById('key-shodan').value     = data.shodanKey;
});

// ── Save keys ────────────────────────────────────────────────────────────
function saveKeys() {
  const vtKey     = document.getElementById('key-vt').value.trim();
  const abuseKey  = document.getElementById('key-abuseipdb').value.trim();
  const shodanKey = document.getElementById('key-shodan').value.trim();

  chrome.storage.sync.set({
    virusTotalKey: vtKey,
    abuseIPDBKey:  abuseKey,
    shodanKey:     shodanKey,
  }, () => {
    const msg = document.getElementById('save-status');
    if (chrome.runtime.lastError) {
      msg.textContent = '✕ Error: ' + chrome.runtime.lastError.message;
      msg.className = 'status-msg error';
    } else {
      msg.textContent = '✓ Saved';
      msg.className = 'status-msg';
    }
    msg.style.display = 'inline';
    setTimeout(() => msg.style.display = 'none', 3000);
  });
}

// ── Toggle visibility ────────────────────────────────────────────────────
function toggleVis(id) {
  const input = document.getElementById(id);
  input.type = input.type === 'password' ? 'text' : 'password';
}

// ── Clear all ────────────────────────────────────────────────────────────
function clearAll() {
  if (!confirm('This will delete all API keys, history, and cached data. Continue?')) return;
  chrome.storage.sync.clear();
  chrome.storage.local.clear();
  chrome.storage.session.clear();
  document.getElementById('key-vt').value       = '';
  document.getElementById('key-abuseipdb').value = '';
  document.getElementById('key-shodan').value   = '';
  alert('All IOCulus data cleared.');
}

// Allow Enter to save
document.querySelectorAll('input').forEach(input => {
  input.addEventListener('keydown', e => { if (e.key === 'Enter') saveKeys(); });
});

// ── Button wiring ─────────────────────────────────────────────────────────
document.getElementById('btn-save').addEventListener('click', saveKeys);
document.getElementById('btn-clear-all').addEventListener('click', clearAll);
document.querySelectorAll('.toggle-visibility').forEach(btn => {
  btn.addEventListener('click', () => toggleVis(btn.dataset.target));
});
