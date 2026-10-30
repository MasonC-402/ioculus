/**
 * IOCulus — Background Service Worker
 * Handles context menus, API orchestration, and message routing.
 */

importScripts('ioc.js'); // PATTERNS, refang, extractIOCs, detectType, isPrivateIP

// ─── Context Menu Setup ───────────────────────────────────────────────────────

function buildMenus() {
  chrome.contextMenus.removeAll(() => {
    // Root item
    chrome.contextMenus.create({
      id: 'ioculus-root',
      title: 'IOCulus',
      contexts: ['selection', 'page', 'link'],
    });

    // Selection-based analysis
    chrome.contextMenus.create({
      id: 'analyze-auto',
      parentId: 'ioculus-root',
      title: 'Analyze Selection (Auto-detect)',
      contexts: ['selection'],
    });
    chrome.contextMenus.create({
      id: 'sep1',
      parentId: 'ioculus-root',
      type: 'separator',
      contexts: ['selection'],
    });
    chrome.contextMenus.create({
      id: 'analyze-ip',
      parentId: 'ioculus-root',
      title: 'Analyze as IP',
      contexts: ['selection'],
    });
    chrome.contextMenus.create({
      id: 'analyze-domain',
      parentId: 'ioculus-root',
      title: 'Analyze as Domain / URL',
      contexts: ['selection'],
    });
    chrome.contextMenus.create({
      id: 'analyze-hash',
      parentId: 'ioculus-root',
      title: 'Analyze as Hash',
      contexts: ['selection'],
    });
    chrome.contextMenus.create({
      id: 'sep2',
      parentId: 'ioculus-root',
      type: 'separator',
      contexts: ['selection', 'page'],
    });

    // Page-level tools
    chrome.contextMenus.create({
      id: 'extract-iocs',
      parentId: 'ioculus-root',
      title: 'Extract IOCs from Page',
      contexts: ['page', 'selection'],
    });
    chrome.contextMenus.create({
      id: 'network-inspector',
      parentId: 'ioculus-root',
      title: 'Network Request Inspector',
      contexts: ['page'],
    });

    // Link analysis
    chrome.contextMenus.create({
      id: 'analyze-link',
      parentId: 'ioculus-root',
      title: 'Analyze Link URL',
      contexts: ['link'],
    });

    // Open panel
    chrome.contextMenus.create({
      id: 'sep3',
      parentId: 'ioculus-root',
      type: 'separator',
      contexts: ['page', 'selection', 'link'],
    });
    chrome.contextMenus.create({
      id: 'open-panel',
      parentId: 'ioculus-root',
      title: 'Open IOCulus Panel',
      contexts: ['page', 'selection', 'link'],
    });
  });
}

chrome.runtime.onInstalled.addListener(buildMenus);
chrome.runtime.onStartup.addListener(buildMenus);

// ─── Context Menu Click Handler ───────────────────────────────────────────────

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  // Ensure side panel is open
  await openPanel(tab);

  let value = '';
  let type  = 'unknown';

  if (info.menuItemId === 'analyze-link') {
    value = info.linkUrl || '';
    type  = 'url';
  } else if (info.menuItemId === 'extract-iocs') {
    queuePanelAction({ action: 'extract-iocs', tabId: tab.id });
    return;
  } else if (info.menuItemId === 'network-inspector') {
    queuePanelAction({ action: 'network-inspector', tabId: tab.id });
    return;
  } else if (info.menuItemId === 'open-panel') {
    return; // panel already opened above
  } else {
    value = (info.selectionText || '').trim();
    if (!value) return;

    if (info.menuItemId === 'analyze-auto')   type = detectType(value);
    else if (info.menuItemId === 'analyze-ip')     type = 'ipv4';
    else if (info.menuItemId === 'analyze-domain') type = detectType(value) === 'url' ? 'url' : 'domain';
    else if (info.menuItemId === 'analyze-hash')   type = detectType(value) !== 'unknown' ? detectType(value) : 'md5';
  }

  sendToPanel({ action: 'analyze', value, type });
  await dispatchAnalysis(value, type);
});

// ─── Panel Communication ──────────────────────────────────────────────────────

async function openPanel(tab) {
  try {
    await chrome.sidePanel.open({ tabId: tab.id });
    await chrome.sidePanel.setOptions({ tabId: tab.id, path: 'panel.html', enabled: true });
  } catch (e) {
    // Side panel may already be open or unsupported
  }
}

function sendToPanel(msg) {
  chrome.runtime.sendMessage({ ...msg, target: 'panel' }).catch(() => {});
}

// Page-level actions requested from the context menu are also stashed in session
// storage: if the side panel was closed, it isn't listening yet when the message
// is sent, so it picks the request up from here once it loads.
function queuePanelAction(msg) {
  chrome.storage.session.set({ pendingPanelAction: { ...msg, ts: Date.now() } });
  sendToPanel(msg);
}

// ─── Analysis Dispatcher ──────────────────────────────────────────────────────

async function dispatchAnalysis(value, type) {
  value = refang(String(value).trim());
  if (!type || type === 'unknown' || type === 'hash') type = detectType(value);
  const keys = await getApiKeys();

  sendToPanel({ action: 'analysis-start', value, type });

  if (type === 'ipv4' || type === 'ipv6') {
    await analyzeIP(value, keys);
  } else if (type === 'domain' || type === 'url') {
    await analyzeDomainOrUrl(value, keys);
  } else if (type === 'md5' || type === 'sha1' || type === 'sha256' || type === 'sha512') {
    await analyzeHash(value, keys);
  } else if (type === 'email') {
    // For email: extract domain and do domain lookup
    const domain = value.split('@')[1];
    if (domain) await analyzeDomainOrUrl(domain, keys);
  } else {
    sendToPanel({ action: 'analysis-error', message: `Unknown IOC type for: ${value}` });
  }
}

// ─── API Key Helper ───────────────────────────────────────────────────────────

async function getApiKeys() {
  return new Promise(resolve => {
    chrome.storage.sync.get(['virusTotalKey', 'abuseIPDBKey', 'shodanKey'], resolve);
  });
}

// ─── API: VirusTotal ──────────────────────────────────────────────────────────

async function vtRequest(endpoint, apiKey) {
  if (!apiKey) return { error: 'VirusTotal API key not configured. Go to Settings.' };
  try {
    const resp = await fetch(`https://www.virustotal.com/api/v3/${endpoint}`, {
      headers: { 'x-apikey': apiKey },
    });
    if (!resp.ok) return { error: `VT HTTP ${resp.status}: ${resp.statusText}` };
    return await resp.json();
  } catch (e) {
    return { error: `VT fetch failed: ${e.message}` };
  }
}

async function vtAnalyzeIP(ip, apiKey) {
  return vtRequest(`ip_addresses/${encodeURIComponent(ip)}`, apiKey);
}

async function vtAnalyzeDomain(domain, apiKey) {
  return vtRequest(`domains/${encodeURIComponent(domain)}`, apiKey);
}

async function vtAnalyzeUrl(url, apiKey) {
  // Submit URL for analysis
  const encoded = btoa(url).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  // Try fetching existing report first
  const result = await vtRequest(`urls/${encoded}`, apiKey);
  if (result.error && result.error.includes('404')) {
    // Submit for new scan
    try {
      const submitResp = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `url=${encodeURIComponent(url)}`,
      });
      const submitData = await submitResp.json();
      return { submitted: true, data: submitData };
    } catch (e) {
      return { error: `VT URL submit failed: ${e.message}` };
    }
  }
  return result;
}

async function vtAnalyzeHash(hash, apiKey) {
  return vtRequest(`files/${encodeURIComponent(hash)}`, apiKey);
}

// ─── API: AbuseIPDB ───────────────────────────────────────────────────────────

async function abuseIPDBLookup(ip, apiKey) {
  if (!apiKey) return { error: 'AbuseIPDB API key not configured. Go to Settings.' };
  try {
    const resp = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
      { headers: { Key: apiKey, Accept: 'application/json' } }
    );
    if (!resp.ok) return { error: `AbuseIPDB HTTP ${resp.status}` };
    return await resp.json();
  } catch (e) {
    return { error: `AbuseIPDB fetch failed: ${e.message}` };
  }
}

// ─── API: Shodan ──────────────────────────────────────────────────────────────

async function shodanLookup(ip, apiKey) {
  if (!apiKey) return { error: 'Shodan API key not configured. Go to Settings.' };
  try {
    const resp = await fetch(
      `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${apiKey}`
    );
    if (resp.status === 404) return { error: 'No Shodan data for this IP.' };
    if (!resp.ok) return { error: `Shodan HTTP ${resp.status}` };
    return await resp.json();
  } catch (e) {
    return { error: `Shodan fetch failed: ${e.message}` };
  }
}

// ─── API: Geo/ASN (ip-api.com, free, no key needed) ──────────────────────────

async function geoLookup(ip) {
  try {
    const resp = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query`);
    if (!resp.ok) return { error: `Geo HTTP ${resp.status}` };
    return await resp.json();
  } catch (e) {
    return { error: `Geo fetch failed: ${e.message}` };
  }
}

// ─── API: WHOIS (whoisjson.com, free tier) ────────────────────────────────────

async function whoisLookup(domain) {
  try {
    const resp = await fetch(`https://whoisjson.com/api/v1/whois?domain=${encodeURIComponent(domain)}`);
    if (!resp.ok) {
      // Fallback to rdap
      return rdapLookup(domain);
    }
    return await resp.json();
  } catch (e) {
    return rdapLookup(domain);
  }
}

async function rdapLookup(domain) {
  try {
    const resp = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
    if (!resp.ok) return { error: `RDAP HTTP ${resp.status}` };
    return await resp.json();
  } catch (e) {
    return { error: `WHOIS/RDAP fetch failed: ${e.message}` };
  }
}

// ─── Orchestrated Analysis Functions ─────────────────────────────────────────

async function analyzeIP(ip, keys) {
  // Fire all requests in parallel
  const [vtResult, abuseResult, shodanResult, geoResult] = await Promise.all([
    vtAnalyzeIP(ip, keys.virusTotalKey),
    abuseIPDBLookup(ip, keys.abuseIPDBKey),
    shodanLookup(ip, keys.shodanKey),
    geoLookup(ip),
  ]);

  sendToPanel({
    action: 'analysis-result',
    type: 'ip',
    value: ip,
    results: {
      virustotal: vtResult,
      abuseipdb:  abuseResult,
      shodan:     shodanResult,
      geo:        geoResult,
    },
  });
}

async function analyzeDomainOrUrl(value, keys) {
  let domain = value;
  let isUrl  = false;

  if (value.startsWith('http://') || value.startsWith('https://')) {
    isUrl = true;
    try { domain = new URL(value).hostname; } catch (_) {}
  }

  const [vtResult, whoisResult] = await Promise.all([
    isUrl ? vtAnalyzeUrl(value, keys.virusTotalKey) : vtAnalyzeDomain(domain, keys.virusTotalKey),
    whoisLookup(domain),
  ]);

  sendToPanel({
    action: 'analysis-result',
    type: isUrl ? 'url' : 'domain',
    value,
    domain,
    results: {
      virustotal: vtResult,
      whois:      whoisResult,
    },
  });
}

async function analyzeHash(hash, keys) {
  const vtResult = await vtAnalyzeHash(hash, keys.virusTotalKey);

  sendToPanel({
    action: 'analysis-result',
    type: 'hash',
    value: hash,
    results: {
      virustotal: vtResult,
    },
  });
}

// ─── Message Router ───────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'analyze') {
    dispatchAnalysis(msg.value, msg.type);
    sendResponse({ ok: true });
    return false;
  }

  if (msg.action === 'extract-iocs-data') {
    // Receives page text (and optional links/resources), returns IOCs
    const iocs = extractIOCs(msg.text, msg.page);
    sendResponse({ iocs });
    return false;
  }

  if (msg.action === 'get-network-data') {
    // Network data is stored per-tab
    chrome.storage.session.get([`net_${msg.tabId}`], data => {
      sendResponse({ requests: data[`net_${msg.tabId}`] || [] });
    });
    return true; // async
  }

  if (msg.action === 'ping') {
    sendResponse({ ok: true });
    return false;
  }

  if (msg.action === 'open-panel') {
    chrome.tabs.query({ active: true, currentWindow: true }, async ([tab]) => {
      if (tab) await openPanel(tab);
    });
    sendResponse({ ok: true });
    return false;
  }

  return false;
});

// ─── Network Request Tracking ─────────────────────────────────────────────────

const MAX_REQUESTS_PER_TAB = 500;

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return; // background requests
    const key = `net_${details.tabId}`;

    chrome.storage.session.get([key], (data) => {
      const requests = data[key] || [];
      const entry = {
        id:          details.requestId,
        url:         details.url,
        method:      details.method,
        type:        details.type,
        timestamp:   details.timeStamp,
        initiator:   details.initiator || '',
        flagged:     isSuspiciousRequest(details),
        flagReason:  getSuspiciousReason(details),
      };
      requests.unshift(entry);
      if (requests.length > MAX_REQUESTS_PER_TAB) requests.length = MAX_REQUESTS_PER_TAB;
      chrome.storage.session.set({ [key]: requests });
    });
  },
  { urls: ['<all_urls>'] },
  ['requestBody']
);

function isSuspiciousRequest(details) {
  const url = details.url.toLowerCase();
  return (
    /\.(exe|dll|bat|ps1|vbs|jar|zip|rar|7z|msi|dmg|pkg|deb|rpm)(\?.*)?$/.test(url) ||
    /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/.test(new URL(details.url).hostname) || // raw IP
    /data:/.test(url) ||
    getSuspiciousReason(details) !== ''
  );
}

function getSuspiciousReason(details) {
  const url = details.url.toLowerCase();
  const hostname = (() => { try { return new URL(details.url).hostname; } catch(_){return '';} })();
  const reasons = [];

  if (/\.(exe|dll|bat|ps1|vbs|jar)(\?.*)?$/.test(url))
    reasons.push('Executable file type');
  if (/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/.test(hostname) && hostname !== 'localhost')
    reasons.push('Raw IP host');
  if (details.type === 'xmlhttprequest' && details.initiator && !details.url.startsWith(details.initiator))
    reasons.push('Cross-origin XHR');
  if (/pastebin\.|paste\.ee|hastebin\.|ghostbin\.co/.test(hostname))
    reasons.push('Paste site');
  if (/ngrok\.|serveo\.net|localhost\.run/.test(hostname))
    reasons.push('Tunnel service');
  if (/\.onion/.test(hostname))
    reasons.push('Onion address');

  return reasons.join('; ');
}

// Clear network data when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([`net_${tabId}`]);
});

// ─── Toolbar Button: Toggle Panel ────────────────────────────────────────────

chrome.action.onClicked.addListener(async (tab) => {
  await openPanel(tab);
});
