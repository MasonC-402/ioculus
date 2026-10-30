# IOCulus

A Chrome/Brave extension for looking up IPs, domains, URLs, and hashes, pulling IOCs out of pages, and watching a tab's network requests. Plain JS, no build step.

## Install

1. Go to `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and pick the `ioculus/` folder.
4. Click the toolbar icon to open or close the side panel.

To pick up code changes, hit **↺ Reload** on the extensions page.

## API keys

Open settings with the ⚙ button in the panel, then add your keys:

| Service | Sign up | Free tier |
| ------- | ------- | --------- |
| VirusTotal | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) | 4 req/min, 500/day |
| AbuseIPDB | [abuseipdb.com/register](https://www.abuseipdb.com/register) | 1,000 checks/day |
| Shodan | [account.shodan.io/register](https://account.shodan.io/register) | Host lookups only, no scanning |

Keys live in `chrome.storage.sync` and only go to their own API.

Geo/ASN ([ip-api.com](http://ip-api.com), 45 req/min) and WHOIS ([RDAP](https://rdap.org)) don't need a key.

## Features

### Right-click menu

Select some text, right-click, and go to **IOCulus**:

- **Analyze Selection (Auto-detect)** figures out whether it's an IP, domain, URL, hash, or email and runs the lookups that apply.
- **Analyze as IP / Domain / Hash** forces a type.
- **Analyze Link URL** (right-click a link) checks where the link goes.
- **Extract IOCs from Page** scans the current page.
- **Network Request Inspector** opens the request log.

### Results

Lookups run in parallel, and each source gets its own collapsible card.

IPs:

- VirusTotal: detections, engine list, reputation, ASN
- AbuseIPDB: confidence score, report count, categories, last reported, TOR flag
- Shodan: open ports, banners, OS, CVEs, ASN
- Geo/ASN: country, city, ISP, ASN, map link

Domains and URLs:

- VirusTotal: detection stats, categories, tags, registrar
- WHOIS (RDAP): registrar, created/expires, nameservers, registrant

Hashes (MD5, SHA1, SHA256, SHA512):

- VirusTotal: detections, file name, type, size, first/last seen, Sigma results

You can also paste anything into the bar at the top of the panel and hit Enter.

### IOC extractor

While this tab is open, it scans the current page and rescans when you switch tabs or a page loads. You can also paste raw text. Defanged values like `hxxp://`, `evil[.]com`, `1.2.3[.]4`, and `user[@]host` get refanged first.

It picks up:

- IPv4 (skips private/reserved) and IPv6
- Domains, from the text and from URLs in it
- URLs
- MD5, SHA1, SHA256, and SHA512 hashes
- Emails, including `mailto:` links
- CVE IDs
- Page links: every `<a href>` in every frame, with external links first
- Page resources: scripts, iframes, form actions, `<link>` tags, embeds, media, and meta-refresh targets

Each item has an Analyze button. Each section has Copy all, and you can export everything as JSON.

### Network inspector

Logs up to 500 requests from the current tab. You can filter by URL or type, or turn on "Flagged only" to show requests that look off:

- Executable downloads (`.exe`, `.ps1`, `.dll`, etc.)
- Hosts that are raw IPs
- Cross-origin XHR
- Paste sites, tunnel services, and `.onion`

Click a request to analyze its URL.

### History

The last 200 lookups are saved locally. Click one to run it again, or export the whole history as JSON.

## Files

```text
ioculus/
├── manifest.json     MV3 manifest
├── background.js     Service worker: context menus, API calls, network tracking
├── ioc.js            IOC detection, refanging, extraction (shared)
├── panel.html        Side panel markup
├── panel.css         Side panel styles
├── panel.js          Side panel logic
├── settings.html     Settings page
├── settings.js       Settings page logic
└── icons/
```

## Rate limits

- VirusTotal: 4 req/min on the free tier. An IP lookup makes one VT call (plus one each to AbuseIPDB, Shodan, and ip-api), so normal use stays under the limit.
- AbuseIPDB: 1,000/day, one per IP lookup.
- Shodan: host lookups work on the free tier. Scanning doesn't.
- ip-api.com: 45/min per IP.

## Privacy

Requests go straight from your browser to each API. Keys are in `chrome.storage.sync`, which syncs to your Google account if you're signed in. History stays in `chrome.storage.local`. Nothing gets sent anywhere else.

## License

[MIT](LICENSE)
