# IOCulus — Analyst Toolkit

A Chromium (Chrome/Brave) extension for cybersecurity analysts. Context-menu-driven reputation lookups, IOC extraction, and network request inspection — no build step, vanilla JS.

---

## Quick Start

### 1. Load the Extension

1. Open Chrome/Brave and navigate to `chrome://extensions`
2. Enable **Developer mode** (toggle, top-right)
3. Click **Load unpacked**
4. Select the `ioculus/` folder
5. The IOCulus icon appears in your toolbar — click it to open or close the side panel (or use the ✕ in the panel header)

### 2. Configure API Keys

Click the extension icon → **⚙ Settings** (or right-click any page → IOCulus → Open IOCulus Panel → ⚙), then enter:

| Key | Where to get it | Free tier |
|-----|----------------|-----------|
| **VirusTotal** | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) | 4 req/min, 500/day |
| **AbuseIPDB** | [abuseipdb.com/register](https://www.abuseipdb.com/register) | 1,000 checks/day |
| **Shodan** | [account.shodan.io/register](https://account.shodan.io/register) | Host lookups (no scanning) |

Keys are stored in `chrome.storage.sync` — synced across your Chrome profile, never sent anywhere except the respective API endpoints.

**No key needed:** Geo/ASN uses [ip-api.com](http://ip-api.com) (free, 45 req/min). WHOIS uses [RDAP](https://rdap.org) (the registries' official WHOIS replacement).

---

## Features

### Context Menu Analysis
Right-click any selected text → **IOCulus** → choose an option:

- **Analyze Selection (Auto-detect)** — auto-detects type (IP, domain, URL, hash, email) and runs all relevant lookups
- **Analyze as IP / Domain / Hash** — force a specific type
- **Analyze Link URL** — right-click any hyperlink to analyze its destination
- **Extract IOCs from Page** — scans the current page for all IOCs
- **Network Request Inspector** — opens the captured request log

### Side Panel — Results Tab
Each analysis query fires parallel API requests. Results appear in collapsible cards:

**IP Analysis:**
- VirusTotal: detection count, gauge, engine list, reputation, ASN
- AbuseIPDB: confidence score, total reports, categories, last report date, TOR flag
- Shodan: open ports, service banners, OS, vulnerabilities (CVEs), ASN
- Geo/ASN: country, city, ISP, ASN, map link

**Domain / URL Analysis:**
- VirusTotal: detection stats, categories, tags, registrar
- WHOIS (RDAP): registrar, creation/expiry dates, nameservers, registrant

**Hash Analysis (MD5 / SHA1 / SHA256):**
- VirusTotal: detection count, file name, type, size, first/last seen, Sigma analysis

### Quick-Analyze Bar
Paste any IOC directly into the bar at the top of the panel and press Enter or click **Analyze**.

### IOC Extractor
Scans the current page automatically whenever the IOC Extractor tab is open (re-scans on tab switch and page load), or paste raw text. Defanged IOCs (`hxxp://`, `evil[.]com`, `1.2.3[.]4`, `user[@]host`) are refanged first. Extracts:
- IPv4 (private/reserved excluded) and IPv6 addresses
- Domains (from text and from URLs in text)
- URLs
- File hashes (MD5, SHA1, SHA256, SHA512)
- Email addresses (including `mailto:` links)
- CVE identifiers
- **Page links** — every `<a href>` on the page (all frames), external links first
- **Page resources** — scripts, iframes, form actions, `<link>`s, embeds, media, meta-refresh targets

Click **Analyze** next to any item to run lookups immediately, **Copy all** per section, or export everything as JSON.

### Network Request Inspector
Captures all requests made by the current tab (up to 500). Features:
- Filter by URL or request type
- "Flagged only" toggle — highlights suspicious requests:
  - Executable file downloads (`.exe`, `.ps1`, `.dll`, etc.)
  - Raw IP hosts
  - Cross-origin XHR
  - Paste sites, tunnel services, `.onion` addresses
- Click any request to analyze its URL

### History
All analyses are saved locally (last 200). Click any entry to re-run the analysis. Export full history as JSON.

---

## File Structure

```
ioculus/
├── manifest.json          # MV3 manifest
├── background.js          # Service worker: context menus, API calls, network tracking
├── ioc.js                 # Shared IOC detection, refanging, and extraction
├── panel.html             # Side panel markup
├── panel.css              # Side panel styles (dark theme)
├── panel.js               # Side panel logic: rendering, IOC UI, network UI, history
├── settings.html          # Options page: API key management
├── settings.js            # Options page logic
└── icons/
    ├── icon16.png
    ├── icon32.png
    ├── icon48.png
    └── icon128.png
```

---

## API Rate Limits & Tips

- **VirusTotal free:** 4 requests/minute. IP, domain, and URL each cost 1 request. Analyzing an IP fires 1 VT request + 1 AbuseIPDB + 1 Shodan + 1 Geo = 4 total across 4 different APIs, so you won't hit VT limits on typical use.
- **AbuseIPDB:** 1,000/day free. Each IP lookup is 1 request.
- **Shodan free:** Host lookups are available. Scanning is not.
- **ip-api.com:** 45 requests/minute per IP, no key needed.

---

## Updating

This is an unpacked extension — just edit files and click **↺ Reload** on the `chrome://extensions` page. No build step required.

---

## Privacy

- All API calls go directly from your browser to the respective API endpoints.
- API keys are stored in `chrome.storage.sync` (encrypted by Chrome, synced to your Google account if signed in).
- Analysis history is stored locally in `chrome.storage.local`.
- No telemetry, no external servers, no ads.

---

## License

[MIT](LICENSE)
