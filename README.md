# passive-recon

Non-invasive vulnerability reconnaissance for IPs and domains.
Read-only / low-impact: only simple GET requests and single TCP connects, plus an
anonymous-FTP login probe with public credentials. **No** brute-force, **no**
fuzzing, **no** exploits, **no** write access.

Python standard library only — no dependencies to install (Python ≥ 3.9).

> ⚠️ Only use against systems for which you have explicit **written authorization**
> to test (scope / engagement).

## What it checks

| Check | Category | Method |
|-------|----------|--------|
| WordPress detection + version | `wordpress` | meta generator, `readme.html`, RSS feed |
| WP user enumeration | `wordpress` | `/wp-json/wp/v2/users` + `/?author=N` (small N) |
| XML-RPC enabled | `wordpress` | GET `/xmlrpc.php` |
| CVE lookup for core & plugins | `wordpress` | WPScan API (key required) |
| Directory listing | `directory-listing` | "Index of /" detection on a small path list + robots paths |
| Interesting robots.txt entries | `robots` | filters out standard entries, highlights "juicy" paths |
| HTTP basic/digest auth prompts | `basic-auth` | 401 + `WWW-Authenticate` |
| Open FTP/SQL/DB ports | `ports` | TCP connect + banner grab (no login) |
| **Anonymous / unauthenticated FTP** | `ports` | anonymous login probe on port 21 (public creds, read-only) |
| **Banner → CVE** | `cve` | detects product+version in banners (HTTP `Server`/`X-Powered-By`, FTP, MySQL/MariaDB…), maps to a CPE and returns matching CVEs via the **NVD API** (sorted by CVSS) |
| Security headers / banner | `headers` | from the root response |
| Fully passive (optional) | `shodan` | Shodan host lookup, **no** contact with the target |

Ports probed: 21 (FTP), 3306 (MySQL/MariaDB), 5432 (PostgreSQL), 1433 (MSSQL),
1521 (Oracle), 27017 (MongoDB), 6379 (Redis), 5984 (CouchDB), 9200 (Elasticsearch),
11211 (Memcached). Customizable via `--ports`.

Banners recognized for CVE lookup: Apache httpd, nginx, OpenSSH, OpenSSL, PHP,
Microsoft IIS, lighttpd, Exim, ProFTPD, vsftpd, Pure-FTPd, MySQL, MariaDB.

## Input formats

Targets can be given as:
- a domain: `example.com`, `https://shop.example.com`
- a single IP: `203.0.113.10`
- a CIDR block: `10.0.0.0/24` (expanded to individual hosts)
- an IP range: `10.0.0.1-50` or `10.0.0.1-10.0.0.50`

Range/CIDR expansion is capped per range (`--max-hosts`, default 1024) to avoid
accidentally scanning huge networks.

## Web UI (host locally)

A nice dark UI in the browser that uses the same scanner and streams results live
per target. Local only (`127.0.0.1`), no external dependencies.

```bash
cd passive-recon
python3 web_app.py            # -> http://127.0.0.1:8787
python3 web_app.py --open     # start and open the browser automatically
python3 web_app.py --port 9000
```

On macOS you can also double-click **`start-web.command`**.

Then open `http://127.0.0.1:8787`: enter targets, confirm authorization, click
"Start scan". API keys are optional under "Advanced options" (empty = server's
ENV / `config.json`). Results are processed locally only and can be saved via
"Export as JSON".

## Usage (CLI)

```bash
# Single target
python3 passive_recon.py example.com

# Multiple targets, an IP, a CIDR and a range
python3 passive_recon.py example.com 203.0.113.10 10.0.0.0/24 10.0.0.1-50

# Targets from a file
python3 passive_recon.py -f targets.txt

# Set the WPScan key (3 ways)
export WPSCAN_API_KEY="your_key"
python3 passive_recon.py example.com
#   ...or
python3 passive_recon.py --wpscan-api-key your_key example.com
#   ...or cp config.example.json config.json  and put it there

# Export results as JSON
python3 passive_recon.py example.com -o results.json

# Fully passive (no contact with the target, Shodan data only)
python3 passive_recon.py --passive-only --shodan-api-key your_key 203.0.113.10

# Non-interactive for scripts/pipelines (only with an engagement!)
python3 passive_recon.py -y example.com
```

Disable banner CVE lookup: `--no-cve`. CVEs per product: `--max-cves N`.
Hosts per range/CIDR: `--max-hosts N`.

## Storing API keys

Priority: `--wpscan-api-key` / `--shodan-api-key` / `--nvd-api-key` →
environment variable `WPSCAN_API_KEY` / `SHODAN_API_KEY` / `NVD_API_KEY` →
`config.json`.

`config.json` is looked up in: `--config <path>` → current directory →
`~/.config/passive-recon/config.json`.

```bash
cp config.example.json config.json
# WPScan key (free):  https://wpscan.com/api  (25 requests/day on the free tier)
# NVD key (free):     https://nvd.nist.gov/developers/request-an-api-key
#   (the CVE lookup also works without an NVD key, just slower:
#    5 vs. 50 requests / 30 s → ~6 s wait per product lookup)
```

## Note on "passive"

Real WP enumeration, directory listing, robots.txt, the anonymous-FTP probe and
port status all require minimal contact with the target. The tool keeps this as
small as possible (single GETs, one TCP connect per port, no retries, no
payloads; the FTP probe uses only public `anonymous` credentials and never
writes). If you want **zero** contact, use `--passive-only` (Shodan).

This tool is intentionally not a full active vulnerability scanner
(OpenVAS/Greenbone, Nessus, Nuclei) — that would be invasive.
