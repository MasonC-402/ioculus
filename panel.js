/**
 * IOCulus — Side Panel JS
 * Renders analysis results, IOC extractor, network inspector, and history.
 */

'use strict';

// ─── State ────────────────────────────────────────────────────────────────────

const state = {
  currentTab:       'results',
  history:          [],          // [{ value, type, timestamp, results }]
  networkRequests:  [],
  netFilter:        '',
  flaggedOnly:      false,
  currentTabId:     null,
  pendingSources:   new Set(),   // tracks which API responses are still loading
  iocPageUrl:       null,          // URL of the page the IOC results belong to
  iocExtracting:    false,
};

// ─── Init ────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initQuickBar();
  initIOCExtractor();
  initNetworkInspector();
  initHistory();
  loadHistory();

  // Get current tab ID for network inspector
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (tab) state.currentTabId = tab.id;
  });

  consumePendingAction();
});

// Context-menu actions sent while the panel was closed are queued in session storage
function consumePendingAction() {
  chrome.storage.session.get('pendingPanelAction', ({ pendingPanelAction: msg }) => {
    if (!msg) return;
    chrome.storage.session.remove('pendingPanelAction');
    if (Date.now() - msg.ts > 15000) return;
    handlePanelAction(msg);
  });
}

function handlePanelAction(msg) {
  if (msg.action === 'extract-iocs') {
    switchTab('iocs');
    extractFromPage(true);
  } else if (msg.action === 'network-inspector') {
    switchTab('network');
  }
}

// Auto-refresh IOC results when the user switches tabs or a page finishes loading
chrome.tabs.onActivated.addListener(({ tabId }) => {
  state.currentTabId = tabId;
  if (state.currentTab === 'iocs') extractFromPage(true);
  if (state.currentTab === 'network') refreshNetwork();
});
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status !== 'complete' || !tab.active) return;
  if (state.currentTab === 'iocs') extractFromPage(true);
});

// ─── Message listener (from background) ──────────────────────────────────────

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.target && msg.target !== 'panel') return;

  switch (msg.action) {
    case 'analyze':
    case 'analysis-start':
      switchTab('results');
      showAnalysisStart(msg.value, msg.type);
      break;
    case 'analysis-result':
      renderResult(msg);
      addHistory(msg);
      break;
    case 'analysis-error':
      showAnalysisError(msg.message);
      break;
    case 'extract-iocs':
    case 'network-inspector':
      chrome.storage.session.remove('pendingPanelAction');
      handlePanelAction(msg);
      break;
  }
});

// ─── Tab Navigation ───────────────────────────────────────────────────────────

function initTabs() {
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });
}

function switchTab(name) {
  state.currentTab = name;
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.tabcontent').forEach(s => s.classList.toggle('active', s.id === `tab-${name}`));

  if (name === 'network') refreshNetwork();
  if (name === 'iocs')    extractFromPage();
  if (name === 'history') renderHistory();
}

// ─── Quick-analyze bar ────────────────────────────────────────────────────────

function initQuickBar() {
  const input = document.getElementById('quick-input');
  const btn   = document.getElementById('quick-submit');

  const run = () => {
    const val = input.value.trim();
    if (!val) return;
    chrome.runtime.sendMessage({ action: 'analyze', value: val, type: detectType(val) });
    switchTab('results');
  };

  btn.addEventListener('click', run);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });

  document.getElementById('btn-clear').addEventListener('click', clearResults);
  document.getElementById('btn-close').addEventListener('click', closePanel);
  document.getElementById('btn-settings').addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });
}

async function closePanel() {
  // chrome.sidePanel.close() exists in Chrome 141+; window.close() works in older versions
  try {
    if (chrome.sidePanel?.close) {
      const win = await chrome.windows.getCurrent();
      await chrome.sidePanel.close({ windowId: win.id });
      return;
    }
  } catch (_) {}
  window.close();
}

// ─── Results Rendering ────────────────────────────────────────────────────────

function clearResults() {
  document.getElementById('results-container').innerHTML = '';
  document.getElementById('results-container').style.display = 'none';
  document.getElementById('results-placeholder').style.display = '';
  state.pendingSources.clear();
}

function showAnalysisStart(value, type) {
  const container = document.getElementById('results-container');
  const placeholder = document.getElementById('results-placeholder');
  container.innerHTML = '';
  container.style.display = '';
  placeholder.style.display = 'none';
  state.pendingSources.clear();

  // Header
  const header = el('div', 'analysis-header');
  header.innerHTML = `
    <span class="analysis-type-label">${esc(type)}</span>
    <span class="analysis-value">${esc(value)}</span>
    <button class="copy-btn">Copy</button>
  `;
  header.querySelector('.copy-btn').addEventListener('click', () => copyToClip(value));
  container.appendChild(header);

  // Skeleton cards for each expected source
  const sources = getExpectedSources(type);
  sources.forEach(src => {
    state.pendingSources.add(src);
    const card = makeCard(src, sourceLabel(src), `<div class="spinner"></div>&nbsp;Loading…`);
    card.id = `card-${src}`;
    container.appendChild(card);
  });
}

function getExpectedSources(type) {
  if (type === 'ipv4' || type === 'ipv6') return ['virustotal','abuseipdb','shodan','geo'];
  if (type === 'domain')                   return ['virustotal','whois'];
  if (type === 'url')                      return ['virustotal','whois'];
  if (type === 'md5' || type === 'sha1' || type === 'sha256' || type === 'sha512') return ['virustotal'];
  if (type === 'email')                    return ['virustotal','whois'];
  return ['virustotal'];
}

function sourceLabel(src) {
  return { virustotal: 'VirusTotal', abuseipdb: 'AbuseIPDB',
           shodan: 'Shodan', geo: 'Geo / ASN', whois: 'WHOIS' }[src] || src;
}

function renderResult(msg) {
  const { type, value, results, domain } = msg;
  const container = document.getElementById('results-container');
  if (!container || container.style.display === 'none') return;

  Object.entries(results).forEach(([src, data]) => {
    state.pendingSources.delete(src);
    const existing = document.getElementById(`card-${src}`);
    const body     = renderSource(src, data, type, value, domain);
    if (existing) {
      existing.querySelector('.result-card-body').innerHTML = '';
      existing.querySelector('.result-card-body').appendChild(body);
    } else {
      const card = makeCard(src, sourceLabel(src), '');
      card.querySelector('.result-card-body').appendChild(body);
      container.appendChild(card);
    }
  });
}

function renderSource(src, data, type, value, domain) {
  if (data.error) return errorFrag(data.error);

  switch (src) {
    case 'virustotal': return renderVT(data, type);
    case 'abuseipdb':  return renderAbuseIPDB(data);
    case 'shodan':     return renderShodan(data);
    case 'geo':        return renderGeo(data);
    case 'whois':      return renderWHOIS(data, domain || value);
    default:           return pre(JSON.stringify(data, null, 2));
  }
}

// ── VirusTotal renderer ────────────────────────────────────────────────────

function renderVT(data, type) {
  const frag = document.createDocumentFragment();

  if (data.submitted) {
    frag.appendChild(infoFrag('URL submitted to VirusTotal for scanning. Check back in a moment.'));
    return frag;
  }

  const attrs = data.data?.attributes;
  if (!attrs) {
    frag.appendChild(errorFrag('Unexpected VirusTotal response format.'));
    return frag;
  }

  const stats = attrs.last_analysis_stats || {};
  const total  = Object.values(stats).reduce((a,b)=>a+b, 0);
  const mal    = (stats.malicious    || 0) + (stats.suspicious || 0);
  const clean  = stats.harmless || 0;

  // Verdict
  const verdictDiv = el('div', '');
  verdictDiv.style.marginBottom = '8px';
  const v = mal > 5 ? 'mal' : mal > 0 ? 'suspect' : total > 0 ? 'clean' : 'unknown';
  verdictDiv.innerHTML = `
    <span class="verdict verdict-${v === 'suspect' ? 'suspect' : v === 'mal' ? 'mal' : v === 'clean' ? 'clean' : 'unknown'}">
      ${v === 'mal' ? '⚠ MALICIOUS' : v === 'suspect' ? '⚠ SUSPICIOUS' : v === 'clean' ? '✓ CLEAN' : '? NO DATA'}
    </span>
    &nbsp;<span style="font-size:11px;color:var(--muted)">${mal}/${total} engines</span>
  `;
  frag.appendChild(verdictDiv);

  // Gauge
  if (total > 0) {
    const gauge = el('div', 'vt-gauge');
    const pct   = Math.round((mal / total) * 100);
    const color = mal > 5 ? 'var(--vt-mal)' : mal > 0 ? 'var(--vt-suspect)' : 'var(--vt-clean)';
    gauge.innerHTML = `
      <div class="vt-gauge-bar"><div class="vt-gauge-fill" style="width:${pct}%;background:${color}"></div></div>
      <div class="vt-gauge-label">${pct}% detection rate · ${stats.malicious||0} malicious · ${stats.suspicious||0} suspicious · ${clean} harmless · ${stats.undetected||0} undetected</div>
    `;
    frag.appendChild(gauge);
  }

  // Key attributes table
  const rows = [];

  if (type === 'ipv4' || type === 'ipv6') {
    pushRow(rows, 'AS Owner',    attrs.as_owner);
    pushRow(rows, 'Network',     attrs.network);
    pushRow(rows, 'Country',     attrs.country);
    pushRow(rows, 'Reputation',  attrs.reputation);
    pushRow(rows, 'Last Seen',   fmtDate(attrs.last_modification_date));
  } else if (type === 'domain' || type === 'url') {
    pushRow(rows, 'Registrar',   attrs.registrar);
    pushRow(rows, 'Created',     fmtDate(attrs.creation_date));
    pushRow(rows, 'Updated',     fmtDate(attrs.last_modification_date));
    pushRow(rows, 'Reputation',  attrs.reputation);
    const cats = attrs.categories ? Object.values(attrs.categories).join(', ') : null;
    pushRow(rows, 'Categories',  cats);
    const tags = attrs.tags?.join(', ') || null;
    pushRow(rows, 'Tags', tags);
  } else if (type === 'md5' || type === 'sha1' || type === 'sha256') {
    pushRow(rows, 'Name',        attrs.meaningful_name || attrs.name);
    pushRow(rows, 'Type',        attrs.type_description);
    pushRow(rows, 'Size',        attrs.size ? `${attrs.size.toLocaleString()} bytes` : null);
    pushRow(rows, 'MD5',         attrs.md5);
    pushRow(rows, 'SHA1',        attrs.sha1);
    pushRow(rows, 'SHA256',      attrs.sha256);
    pushRow(rows, 'First Seen',  fmtDate(attrs.first_submission_date));
    pushRow(rows, 'Last Seen',   fmtDate(attrs.last_submission_date));
    pushRow(rows, 'Times Seen',  attrs.times_submitted);
    if (attrs.sigma_analysis_summary) {
      const sigs = Object.entries(attrs.sigma_analysis_summary).map(([k,v])=>`${k}: ${v}`).join(', ');
      pushRow(rows, 'Sigma', sigs);
    }
  }

  if (rows.length) frag.appendChild(kvTable(rows));

  // Detected engines (collapsed list)
  const engines = attrs.last_analysis_results ? Object.entries(attrs.last_analysis_results) : [];
  const detected = engines.filter(([,r]) => r.category === 'malicious' || r.category === 'suspicious');
  if (detected.length) {
    const section = el('div', 'vt-engine-list');
    section.innerHTML = `<div style="font-size:10px;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:.3px">Detections (${detected.length})</div>`;
    detected.slice(0, 30).forEach(([engine, res]) => {
      const row = el('div', 'vt-engine-row');
      row.innerHTML = `<span class="vt-engine-name">${esc(engine)}</span><span class="vt-engine-result detected">${esc(res.result||res.category)}</span>`;
      section.appendChild(row);
    });
    if (detected.length > 30) {
      const more = el('div', '');
      more.style.cssText = 'font-size:10px;color:var(--muted);margin-top:4px;';
      more.textContent = `…and ${detected.length - 30} more`;
      section.appendChild(more);
    }
    frag.appendChild(section);
  }

  return frag;
}

// ── AbuseIPDB renderer ────────────────────────────────────────────────────

function renderAbuseIPDB(data) {
  const frag = document.createDocumentFragment();
  const d = data.data;
  if (!d) return errorFrag('No data returned from AbuseIPDB.');

  const score = d.abuseConfidenceScore || 0;
  const scoreColor = score > 75 ? 'var(--vt-mal)' : score > 25 ? 'var(--vt-suspect)' : 'var(--vt-clean)';

  const scoreDiv = el('div', '');
  scoreDiv.style.marginBottom = '8px';
  scoreDiv.innerHTML = `
    <span class="verdict ${score > 75 ? 'verdict-mal' : score > 25 ? 'verdict-suspect' : 'verdict-clean'}">
      Abuse Score: ${score}%
    </span>
  `;
  frag.appendChild(scoreDiv);

  const rows = [];
  pushRow(rows, 'Total Reports', d.totalReports);
  pushRow(rows, 'Distinct Users', d.numDistinctUsers);
  pushRow(rows, 'Last Report',   d.lastReportedAt ? new Date(d.lastReportedAt).toLocaleString() : null);
  pushRow(rows, 'ISP',           d.isp);
  pushRow(rows, 'Domain',        d.domain);
  pushRow(rows, 'Country',       d.countryCode);
  pushRow(rows, 'Usage Type',    d.usageType);
  pushRow(rows, 'Whitelisted',   d.isWhitelisted ? 'Yes' : 'No');
  pushRow(rows, 'TOR',           d.isTor ? '⚠ YES' : 'No');
  frag.appendChild(kvTable(rows));

  // Recent reports
  if (d.reports && d.reports.length > 0) {
    const section = el('div', '');
    section.style.marginTop = '8px';
    section.innerHTML = `<div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.3px;margin-bottom:4px">Recent Reports (${d.reports.length})</div>`;
    const list = el('div', 'vt-engine-list');
    d.reports.slice(0, 10).forEach(r => {
      const row = el('div', 'vt-engine-row');
      const cats = (r.categories || []).join(', ') || 'Unspecified';
      row.innerHTML = `
        <span class="vt-engine-name" style="color:var(--muted)">${new Date(r.reportedAt).toLocaleDateString()}</span>
        <span class="vt-engine-result" style="color:var(--warn)">${esc(cats)}</span>
      `;
      list.appendChild(row);
    });
    section.appendChild(list);
    frag.appendChild(section);
  }

  return frag;
}

// ── Shodan renderer ────────────────────────────────────────────────────────

function renderShodan(data) {
  const frag = document.createDocumentFragment();
  if (data.error && data.error.includes('No Shodan')) {
    frag.appendChild(infoFrag('No Shodan data for this host.'));
    return frag;
  }
  if (data.error) return errorFrag(data.error);

  const rows = [];
  pushRow(rows, 'Hostnames',  (data.hostnames || []).join(', ') || null);
  pushRow(rows, 'Domains',    (data.domains   || []).join(', ') || null);
  pushRow(rows, 'Country',    data.country_name);
  pushRow(rows, 'City',       data.city);
  pushRow(rows, 'ISP',        data.isp);
  pushRow(rows, 'Org',        data.org);
  pushRow(rows, 'ASN',        data.asn);
  pushRow(rows, 'OS',         data.os);
  pushRow(rows, 'Last Update',data.last_update ? new Date(data.last_update).toLocaleString() : null);
  pushRow(rows, 'Vuln Count', data.vulns ? Object.keys(data.vulns).length : null);
  frag.appendChild(kvTable(rows));

  // Open ports
  if (data.ports && data.ports.length) {
    const portSection = el('div', '');
    portSection.style.marginTop = '8px';
    portSection.innerHTML = `<div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.3px;margin-bottom:4px">Open Ports (${data.ports.length})</div>`;
    const portList = el('div', 'port-list');
    data.ports.forEach(p => {
      const chip = el('span', 'port-chip');
      chip.textContent = p;
      chip.title = `Port ${p}`;
      portList.appendChild(chip);
    });
    portSection.appendChild(portList);
    frag.appendChild(portSection);
  }

  // Vulnerabilities
  if (data.vulns && Object.keys(data.vulns).length) {
    const vulnSection = el('div', '');
    vulnSection.style.marginTop = '8px';
    vulnSection.innerHTML = `<div style="font-size:10px;color:var(--danger);text-transform:uppercase;letter-spacing:.3px;margin-bottom:4px">⚠ Vulnerabilities (${Object.keys(data.vulns).length})</div>`;
    const tagList = el('div', 'tag-list');
    Object.keys(data.vulns).forEach(cve => {
      const tag = el('span', 'tag mal');
      tag.textContent = cve;
      tagList.appendChild(tag);
    });
    vulnSection.appendChild(tagList);
    frag.appendChild(vulnSection);
  }

  // Service banners (first 5)
  if (data.data && data.data.length) {
    const bannerSection = el('div', '');
    bannerSection.style.marginTop = '8px';
    bannerSection.innerHTML = `<div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.3px;margin-bottom:4px">Service Banners</div>`;
    data.data.slice(0, 5).forEach(svc => {
      const b = el('div', 'banner-entry');
      const portStr = svc.port ? `${svc.port}/${svc.transport||'tcp'}` : '';
      const product = [svc.product, svc.version].filter(Boolean).join(' ');
      b.innerHTML = `<div class="banner-port">${esc(portStr)} ${esc(product)} ${svc.cpe ? `<span style="color:var(--muted);font-size:9px">${esc(svc.cpe)}</span>` : ''}</div>`;
      if (svc.data) {
        const bd = el('div', 'banner-data');
        bd.textContent = svc.data.substring(0, 500);
        b.appendChild(bd);
      }
      bannerSection.appendChild(b);
    });
    frag.appendChild(bannerSection);
  }

  return frag;
}

// ── Geo/ASN renderer ───────────────────────────────────────────────────────

function renderGeo(data) {
  const frag = document.createDocumentFragment();
  if (data.status === 'fail') return errorFrag(data.message || 'Geo lookup failed.');

  const rows = [];
  pushRow(rows, 'IP',        data.query);
  pushRow(rows, 'Country',   data.country ? `${data.country} (${data.countryCode})` : null);
  pushRow(rows, 'Region',    data.regionName);
  pushRow(rows, 'City',      data.city);
  pushRow(rows, 'ZIP',       data.zip);
  pushRow(rows, 'Timezone',  data.timezone);
  pushRow(rows, 'ISP',       data.isp);
  pushRow(rows, 'Org',       data.org);
  pushRow(rows, 'ASN',       data.as);
  pushRow(rows, 'AS Name',   data.asname);
  if (data.lat && data.lon) {
    const mapUrl = `https://maps.google.com/?q=${data.lat},${data.lon}`;
    rows.push(['Coords', `${data.lat}, ${data.lon} <a class="map-link" href="${mapUrl}" target="_blank">↗ Map</a>`]);
  }
  const table = kvTable(rows);
  // Allow HTML in coords row (for the map link)
  frag.appendChild(table);

  return frag;
}

// ── WHOIS renderer ─────────────────────────────────────────────────────────

function renderWHOIS(data, domain) {
  const frag = document.createDocumentFragment();
  if (data.error) return errorFrag(data.error);

  // RDAP response; values come from registries, so escape them (kvTable renders HTML)
  const rows = [];

  if (data.ldhName || data.handle) {
    // RDAP format
    pushRow(rows, 'Domain',    esc((data.ldhName || domain).toLowerCase()));
    pushRow(rows, 'Handle',    esc(data.handle));
    if (data.events) {
      data.events.forEach(e => {
        pushRow(rows, esc(e.eventAction), esc(fmtWhoisDate(e.eventDate)));
      });
    }
    if (data.nameservers) {
      pushRow(rows, 'Name Servers', esc(data.nameservers.map(ns => ns.ldhName).join(', ')));
    }
    if (data.status) {
      pushRow(rows, 'Status', esc(Array.isArray(data.status) ? data.status.join(', ') : data.status));
    }
    if (data.entities) {
      data.entities.forEach(ent => {
        const roles = (ent.roles || []).join('/');
        const name  = ent.vcardArray?.[1]?.find(v => v[0]==='fn')?.[3] || ent.handle;
        if (name) pushRow(rows, esc(roles || 'Entity'), esc(name));
      });
    }
  }

  if (rows.length) {
    frag.appendChild(kvTable(rows));
  } else {
    // Fallback: raw JSON
    const rawDiv = el('div', 'whois-raw');
    rawDiv.textContent = JSON.stringify(data, null, 2).substring(0, 3000);
    frag.appendChild(rawDiv);
  }

  return frag;
}

function fmtWhoisDate(d) {
  if (!d) return null;
  if (Array.isArray(d)) d = d[0];
  try { return new Date(d).toLocaleString(); } catch(_) { return d; }
}

// ─── Analysis error helper ────────────────────────────────────────────────────

function showAnalysisError(message) {
  const container = document.getElementById('results-container');
  if (container) {
    const e = errorFrag(message);
    const wrapper = el('div', '');
    wrapper.appendChild(e);
    container.appendChild(wrapper);
  }
}

// ─── IOC Extractor ───────────────────────────────────────────────────────────

function initIOCExtractor() {
  document.getElementById('btn-extract-page').addEventListener('click', extractFromPage);
  document.getElementById('btn-extract-text').addEventListener('click', () => {
    const ta = document.getElementById('ioc-paste-area');
    if (ta.style.display === 'none') {
      ta.style.display = '';
      ta.focus();
    } else {
      const text = ta.value;
      if (text.trim()) {
        extractFromText(text);
      } else {
        ta.style.display = 'none';
      }
    }
  });
}

/**
 * Runs in the page (all frames). Self-contained: no closures over panel code.
 * Collects visible text plus every link and loaded resource URL.
 */
function collectPageData() {
  const abs = (u) => { try { return new URL(u, document.baseURI).href; } catch (_) { return null; } };
  const links = [];
  const resources = [];
  const addRes = (kind, u) => { const url = u && abs(u.trim()); if (url) resources.push({ kind, url }); };

  document.querySelectorAll('a[href], area[href]').forEach(a => {
    const url = abs(a.getAttribute('href'));
    if (url) links.push({ url, text: (a.innerText || a.title || '').trim().replace(/\s+/g, ' ').slice(0, 120) });
  });
  document.querySelectorAll('script[src]').forEach(e => addRes('script', e.getAttribute('src')));
  document.querySelectorAll('iframe[src], frame[src]').forEach(e => addRes('iframe', e.getAttribute('src')));
  document.querySelectorAll('form[action]').forEach(e => addRes('form', e.getAttribute('action')));
  document.querySelectorAll('link[href]').forEach(e => addRes(`link:${e.rel || 'other'}`, e.getAttribute('href')));
  document.querySelectorAll('embed[src], object[data]').forEach(e => addRes('object', e.getAttribute('src') || e.getAttribute('data')));
  document.querySelectorAll('img[src], video[src], audio[src], source[src]').forEach(e => addRes(e.tagName.toLowerCase(), e.getAttribute('src')));
  document.querySelectorAll('meta[http-equiv="refresh" i]').forEach(e => {
    const m = /url\s*=\s*['"]?([^'";]+)/i.exec(e.content || '');
    if (m) addRes('meta-refresh', m[1]);
  });

  return {
    url:   location.href,
    title: document.title,
    text:  (document.body ? document.body.innerText : '') || '',
    links,
    resources,
  };
}

async function extractFromPage(force = false) {
  const resultEl = document.getElementById('ioc-results');

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) { resultEl.innerHTML = '<div class="error-msg">No active tab found.</div>'; return; }

  // Opening the tab again shouldn't re-scan the same page unless asked
  if (!force && state.iocPageUrl === tab.url) return;
  if (state.iocExtracting) return;
  state.iocExtracting = true;
  resultEl.innerHTML = '<div class="spinner"></div>&nbsp;Scanning page…';

  try {
    let frames;
    try {
      frames = await chrome.scripting.executeScript({ target: { tabId: tab.id, allFrames: true }, func: collectPageData });
    } catch (_) {
      // Some frames may be inaccessible; fall back to the top frame only
      frames = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: collectPageData });
    }

    const data = frames.map(f => f.result).filter(Boolean);
    if (!data.length) throw new Error('no data');

    const top  = data[0];
    const text = [top.title, ...data.map(d => d.text)].join('\n');
    const page = {
      url:       top.url,
      links:     data.flatMap(d => d.links),
      resources: data.flatMap(d => d.resources),
    };

    state.iocPageUrl = tab.url;
    renderIOCs(extractIOCs(text, page), top.url);
  } catch (e) {
    state.iocPageUrl = null;
    resultEl.innerHTML = '<div class="error-msg">Cannot access this page (restricted URL such as chrome://, the Web Store, or a PDF viewer).</div>';
  } finally {
    state.iocExtracting = false;
  }
}

function extractFromText(text) {
  state.iocPageUrl = null;
  renderIOCs(extractIOCs(text), null);
}

const IOC_SECTIONS = [
  { key: 'ips',       label: 'IP Addresses' },
  { key: 'domains',   label: 'Domains' },
  { key: 'urls',      label: 'URLs in Text' },
  { key: 'hashes',    label: 'File Hashes' },
  { key: 'emails',    label: 'Email Addresses' },
  { key: 'cves',      label: 'CVEs' },
  { key: 'links',     label: 'Page Links' },
  { key: 'resources', label: 'Page Resources (scripts, iframes, forms…)' },
];

const IOC_RENDER_LIMIT = 500;

function renderIOCs(iocs, sourceUrl) {
  const container = document.getElementById('ioc-results');
  container.innerHTML = '';
  container.classList.remove('placeholder');

  if (sourceUrl) {
    const src = el('div', 'ioc-source');
    src.textContent = `Source: ${sourceUrl}`;
    src.title = sourceUrl;
    container.appendChild(src);
  }

  const total = IOC_SECTIONS.reduce((a, { key }) => a + (iocs[key] || []).length, 0);
  if (total === 0) {
    container.appendChild(infoFrag('No IOCs or links found.'));
    return;
  }

  IOC_SECTIONS.forEach(({ key, label }) => {
    const items = (iocs[key] || []).map(i => (typeof i === 'string' ? { value: i } : i));
    if (!items.length) return;

    const section = el('div', 'ioc-section');
    const title   = el('div', 'ioc-section-title');
    title.innerHTML = `${esc(label)} <span class="ioc-count-badge">${items.length}</span>`;
    const copyAll = el('button', 'ioc-action-btn ioc-copy-all');
    copyAll.textContent = 'Copy all';
    copyAll.addEventListener('click', () => copyToClip(items.map(i => i.value).join('\n')));
    title.appendChild(copyAll);
    section.appendChild(title);

    const list = el('div', 'ioc-list');
    items.slice(0, IOC_RENDER_LIMIT).forEach(({ value, meta, external }) => {
      const row = el('div', 'ioc-item');
      const valSpan = el('span', 'ioc-value');
      valSpan.textContent = value;
      valSpan.title = meta ? `${value}\n${meta}` : value;

      if (meta) {
        const metaSpan = el('span', 'ioc-meta');
        metaSpan.textContent = meta;
        valSpan.appendChild(metaSpan);
      }
      if (external === false) row.classList.add('internal');

      const actions = el('div', 'ioc-actions');
      const type = detectType(value);

      if (type !== 'cve' && type !== 'unknown') {
        const analyzeBtn = el('button', 'ioc-action-btn');
        analyzeBtn.textContent = 'Analyze';
        analyzeBtn.addEventListener('click', () => {
          chrome.runtime.sendMessage({ action: 'analyze', value, type });
          switchTab('results');
        });
        actions.appendChild(analyzeBtn);
      }

      const copyBtn = el('button', 'ioc-action-btn copy-btn');
      copyBtn.textContent = 'Copy';
      copyBtn.addEventListener('click', () => copyToClip(value));
      actions.appendChild(copyBtn);

      row.appendChild(valSpan);
      row.appendChild(actions);
      list.appendChild(row);
    });
    if (items.length > IOC_RENDER_LIMIT) {
      list.appendChild(infoFrag(`…${items.length - IOC_RENDER_LIMIT} more (included in Copy all / Export).`));
    }
    section.appendChild(list);
    container.appendChild(section);
  });

  // Export all
  const exportBar = el('div', 'toolbar');
  exportBar.style.marginTop = '10px';
  const exportBtn = el('button', '');
  exportBtn.textContent = 'Export IOCs as JSON';
  exportBtn.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify({ source: sourceUrl, ...iocs }, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = 'iocs.json'; a.click();
    URL.revokeObjectURL(url);
  });
  exportBar.appendChild(exportBtn);
  container.appendChild(exportBar);
}

// ─── Network Inspector ────────────────────────────────────────────────────────

function initNetworkInspector() {
  document.getElementById('btn-refresh-network').addEventListener('click', refreshNetwork);
  document.getElementById('chk-flagged-only').addEventListener('change', e => {
    state.flaggedOnly = e.target.checked;
    renderNetworkList();
  });
  document.getElementById('net-filter').addEventListener('input', e => {
    state.netFilter = e.target.value.toLowerCase();
    renderNetworkList();
  });
}

function refreshNetwork() {
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (!tab) return;
    state.currentTabId = tab.id;
    chrome.runtime.sendMessage({ action: 'get-network-data', tabId: tab.id }, (resp) => {
      if (resp && resp.requests) {
        state.networkRequests = resp.requests;
        renderNetworkList();
      }
    });
  });
}

function renderNetworkList() {
  const container = document.getElementById('network-list');
  let reqs = state.networkRequests;

  if (state.flaggedOnly) reqs = reqs.filter(r => r.flagged);
  if (state.netFilter)   reqs = reqs.filter(r =>
    r.url.toLowerCase().includes(state.netFilter) ||
    (r.type||'').toLowerCase().includes(state.netFilter)
  );

  document.getElementById('network-count').textContent =
    `${reqs.length} / ${state.networkRequests.length} requests`;

  if (!reqs.length) {
    container.innerHTML = `<div class="placeholder">${state.networkRequests.length === 0
      ? 'No requests captured yet. Browse a page with the panel open.'
      : 'No requests match the filter.'}</div>`;
    return;
  }

  container.innerHTML = '';
  const frag = document.createDocumentFragment();

  reqs.forEach(req => {
    const row = el('div', `net-row${req.flagged ? ' flagged' : ''}`);
    row.title = req.url;

    const top = el('div', 'net-row-top');
    const method = el('span', `net-method ${(req.method||'GET').toLowerCase()}`);
    method.textContent = req.method || 'GET';

    const typeBadge = el('span', 'net-type-badge');
    typeBadge.textContent = req.type || '';

    const urlSpan = el('span', 'net-url');
    urlSpan.textContent = req.url;

    top.appendChild(method);
    top.appendChild(typeBadge);
    top.appendChild(urlSpan);

    if (req.flagged) {
      const flag = el('span', 'net-flag-badge');
      flag.textContent = '⚠';
      top.appendChild(flag);
    }

    row.appendChild(top);

    const detail = el('div', 'net-row-detail');
    detail.textContent = new Date(req.timestamp).toLocaleTimeString();
    if (req.initiator) detail.textContent += ` · ${req.initiator}`;
    row.appendChild(detail);

    if (req.flagged && req.flagReason) {
      const reason = el('div', 'net-flag-reason');
      reason.textContent = `⚠ ${req.flagReason}`;
      row.appendChild(reason);
    }

    // Click: analyze the domain/URL
    row.addEventListener('click', () => {
      const val = req.url;
      const type = 'url';
      chrome.runtime.sendMessage({ action: 'analyze', value: val, type });
      switchTab('results');
    });

    frag.appendChild(row);
  });

  container.appendChild(frag);
}

// ─── History ─────────────────────────────────────────────────────────────────

function initHistory() {
  document.getElementById('btn-clear-history').addEventListener('click', () => {
    state.history = [];
    saveHistory();
    renderHistory();
  });
  document.getElementById('btn-export-history').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(state.history, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = 'ioculus-history.json'; a.click();
    URL.revokeObjectURL(url);
  });
}

function addHistory(msg) {
  const entry = {
    value:     msg.value,
    type:      msg.type,
    timestamp: Date.now(),
    results:   msg.results,
  };
  state.history.unshift(entry);
  if (state.history.length > 200) state.history.pop();
  saveHistory();
  if (state.currentTab === 'history') renderHistory();
}

function saveHistory() {
  chrome.storage.local.set({ ioculusHistory: state.history.slice(0, 200) });
}

function loadHistory() {
  chrome.storage.local.get(['ioculusHistory'], data => {
    if (data.ioculusHistory) state.history = data.ioculusHistory;
  });
}

function renderHistory() {
  const container = document.getElementById('history-list');
  if (!state.history.length) {
    container.innerHTML = '<div class="placeholder">No history yet.</div>';
    return;
  }
  container.innerHTML = '';
  const frag = document.createDocumentFragment();
  state.history.forEach(entry => {
    const item = el('div', 'history-item');
    const badge = el('span', 'history-type-badge');
    badge.textContent = entry.type;

    const val = el('span', 'history-value');
    val.textContent = entry.value;

    const time = el('span', 'history-time');
    time.textContent = new Date(entry.timestamp).toLocaleString();

    item.appendChild(badge);
    item.appendChild(val);
    item.appendChild(time);

    item.addEventListener('click', () => {
      switchTab('results');
      chrome.runtime.sendMessage({ action: 'analyze', value: entry.value, type: entry.type });
    });

    frag.appendChild(item);
  });
  container.appendChild(frag);
}

// ─── DOM helpers ─────────────────────────────────────────────────────────────

function el(tag, cls) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  return e;
}

function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

function pre(text) {
  const d = el('div', 'whois-raw');
  d.textContent = text;
  return d;
}

function errorFrag(msg) {
  const d = el('div', 'error-msg');
  d.textContent = msg;
  return d;
}

function infoFrag(msg) {
  const d = el('div', 'info-msg');
  d.textContent = msg;
  return d;
}

function makeCard(id, title, bodyHTML) {
  const card   = el('div', 'result-card');
  const header = el('div', 'result-card-header');
  header.innerHTML = `
    <span class="result-card-title">
      <span class="card-source-badge">${esc(title)}</span>
    </span>
    <span class="result-card-toggle">▾</span>
  `;
  const body = el('div', 'result-card-body');
  body.innerHTML = bodyHTML;

  header.addEventListener('click', () => {
    const collapsed = body.classList.toggle('collapsed');
    header.querySelector('.result-card-toggle').textContent = collapsed ? '▸' : '▾';
  });

  card.appendChild(header);
  card.appendChild(body);
  return card;
}

function kvTable(rows) {
  const table = el('table', 'kv-table');
  rows.forEach(([k, v]) => {
    if (v == null || v === '' || v === 'null' || v === 'undefined') return;
    const tr = el('tr', '');
    const td1 = el('td', '');
    td1.textContent = k;
    const td2 = el('td', '');
    td2.innerHTML = String(v); // allow HTML (e.g. map link)
    tr.appendChild(td1);
    tr.appendChild(td2);
    table.appendChild(tr);
  });
  return table;
}

function pushRow(rows, key, value) {
  rows.push([key, value]);
}

function fmtDate(ts) {
  if (!ts) return null;
  try { return new Date(ts * 1000).toLocaleString(); } catch(_) { return ts; }
}

function copyToClip(text) {
  navigator.clipboard.writeText(text).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  });
}

