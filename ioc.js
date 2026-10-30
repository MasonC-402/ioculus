// IOC detection and extraction, shared by background.js (importScripts)
// and panel.html (<script>).

'use strict';

const TLDS = [
  'com','net','org','io','gov','edu','mil','int','arpa','info','biz','name','pro','mobi','travel',
  'museum','coop','aero','jobs','cat','post','tel','xxx','geo','map','asia',
  'co','uk','us','ca','de','fr','it','es','nl','be','ch','at','se','no','dk','fi','pl','cz','pt',
  'ru','su','ua','by','kz','cn','hk','tw','jp','kr','kp','in','pk','ir','iq','sa','ae','il','tr',
  'br','ar','mx','cl','au','nz','za','ng','eg','eu','ly','to','gg','is','ms','sh','su','vn','th',
  'id','my','sg','ph','ro','hu','gr','bg','rs','hr','lt','lv','ee','sk','si','ie',
  'xyz','top','club','online','site','tech','app','dev','ai','cloud','me','tv','cc','tk','ml',
  'ga','cf','gq','pw','ws','link','live','shop','store','icu','buzz','sbs','cfd','zip','mov',
  'lol','vip','work','space','website','fun','click','download','support','life','world',
  'today','email','digital','network','services','solutions','host','press','rest','bond',
  'cyou','monster','quest','rocks','gdn','onion','bit','su',
];

const PATTERNS = {
  ipv4:   /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
  // Loose candidate; each match is validated in isValidIPv6()
  ipv6:   /(?<![\w:.])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])/g,
  domain: new RegExp(`\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:${[...new Set(TLDS)].join('|')})\\b(?![.-]?\\w)`, 'gi'),
  url:    /\b(?:https?|ftp):\/\/[^\s"'<>`]+/gi,
  md5:    /\b[0-9a-fA-F]{32}\b/g,
  sha1:   /\b[0-9a-fA-F]{40}\b/g,
  sha256: /\b[0-9a-fA-F]{64}\b/g,
  sha512: /\b[0-9a-fA-F]{128}\b/g,
  email:  /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
  cve:    /\bCVE-\d{4}-\d{4,7}\b/gi,
};

/** Undo common defanging: hxxp://, [.], (.), [dot], [:], [@], [at] … */
function refang(text) {
  return text
    .replace(/\bh(?:xx|XX|\*\*)p(s?)(\[?:\]?\/\/|:\/\/)/g, 'http$1://')
    .replace(/\bfxp(\[?:\]?\/\/)/gi, 'ftp://')
    .replace(/\[:\]\/\//g, '://')
    .replace(/\[(?:\.|dot)\]|\((?:\.|dot)\)|\{(?:\.|dot)\}/gi, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\[(?:@|at)\]|\((?:@|at)\)/gi, '@');
}

function isValidIPv6(candidate) {
  if (!candidate.includes('::') && candidate.split(':').length !== 8) return false;
  if (candidate === '::' || candidate === '::1') return false;
  if (candidate.replace(/:/g, '').length < 3) return false;
  try { new URL(`http://[${candidate}]/`); return true; } catch (_) { return false; }
}

function isPrivateIP(ip) {
  const p = ip.split('.').map(Number);
  return (
    p[0] === 10 || p[0] === 127 || p[0] === 0 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 169 && p[1] === 254) ||
    p[0] >= 224
  );
}

function cleanUrl(u) {
  // Strip trailing punctuation that is almost never part of the URL
  let out = u.replace(/[.,;:!?'"]+$/, '');
  // Drop an unbalanced trailing ) or ]
  for (const [open, close] of [['(', ')'], ['[', ']']]) {
    while (out.endsWith(close) && out.split(open).length < out.split(close).length) out = out.slice(0, -1);
  }
  return out;
}

function hostOf(u) {
  try { return new URL(u).hostname.replace(/^\[|\]$/g, '').toLowerCase(); } catch (_) { return ''; }
}

function matchAll(pattern, str) {
  pattern.lastIndex = 0;
  return str.match(pattern) || [];
}

function uniq(arr) { return [...new Set(arr)]; }

/**
 * Extract IOCs from page text, plus (optionally) links and resources collected from the DOM.
 * Returns { ips, domains, urls, hashes, emails, cves, links, resources }
 */
function extractIOCs(text, page = {}) {
  text = refang(text || '');

  const urls   = uniq(matchAll(PATTERNS.url, text).map(cleanUrl));
  const emails = uniq(matchAll(PATTERNS.email, text).map(e => e.toLowerCase()));

  // mailto: links count as email IOCs
  for (const l of page.links || []) {
    if (/^mailto:/i.test(l.url)) {
      const addr = decodeURIComponent(l.url.slice(7).split('?')[0]).toLowerCase();
      if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(addr) && !emails.includes(addr)) emails.push(addr);
    }
  }

  const ipv4 = uniq(matchAll(PATTERNS.ipv4, text)).filter(ip => !isPrivateIP(ip));
  const ipv6 = uniq(matchAll(PATTERNS.ipv6, text)).filter(isValidIPv6);

  // Domains: those written in the text plus hostnames of URLs in the text
  const emailDomains = new Set(emails.map(e => e.split('@')[1]));
  const textDomains  = matchAll(PATTERNS.domain, text).map(d => d.toLowerCase())
    .filter(d => !emailDomains.has(d));
  const urlDomains   = urls.map(hostOf).filter(h => h && !/^[\d.]+$/.test(h) && !h.includes(':'));
  const domains      = uniq([...textDomains, ...urlDomains]);

  const hashes = uniq([
    ...matchAll(PATTERNS.sha512, text),
    ...matchAll(PATTERNS.sha256, text),
    ...matchAll(PATTERNS.sha1, text),
    ...matchAll(PATTERNS.md5, text),
  ].map(h => h.toLowerCase()));

  const cves = uniq(matchAll(PATTERNS.cve, text).map(c => c.toUpperCase()));

  // Links (anchors) and resources (scripts, iframes, forms…) from the DOM
  const pageHost = hostOf(page.url || '');
  const seenLinks = new Set();
  const links = [];
  for (const l of page.links || []) {
    if (!/^(?:https?|ftp):/i.test(l.url) || seenLinks.has(l.url)) continue;
    seenLinks.add(l.url);
    links.push({ value: l.url, meta: l.text || '', external: hostOf(l.url) !== pageHost });
  }
  links.sort((a, b) => b.external - a.external);

  const seenRes = new Set();
  const resources = [];
  for (const r of page.resources || []) {
    if (!/^(?:https?|ftp|wss?):/i.test(r.url)) continue;
    const key = `${r.kind}|${r.url}`;
    if (seenRes.has(key)) continue;
    seenRes.add(key);
    resources.push({ value: r.url, meta: r.kind, external: hostOf(r.url) !== pageHost });
  }
  resources.sort((a, b) => b.external - a.external);

  return { ips: [...ipv4, ...ipv6], domains, urls, hashes, emails, cves, links, resources };
}

/**
 * Determine the type of a single IOC string.
 * Returns one of: 'ipv4','ipv6','url','sha512','sha256','sha1','md5','email','cve','domain','unknown'
 */
function detectType(raw) {
  const t = refang(String(raw).trim());
  const full = (re) => new RegExp(`^(?:${re.source})$`, 'i').test(t);
  if (full(PATTERNS.ipv4))              return 'ipv4';
  if (t.includes(':') && isValidIPv6(t)) return 'ipv6';
  if (/^(?:https?|ftp):\/\//i.test(t))  return 'url';
  if (/^[0-9a-f]{128}$/i.test(t))       return 'sha512';
  if (/^[0-9a-f]{64}$/i.test(t))        return 'sha256';
  if (/^[0-9a-f]{40}$/i.test(t))        return 'sha1';
  if (/^[0-9a-f]{32}$/i.test(t))        return 'md5';
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(t)) return 'email';
  if (/^CVE-\d{4}-\d{4,7}$/i.test(t))   return 'cve';
  if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(t)) return 'domain';
  return 'unknown';
}
