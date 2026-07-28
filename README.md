# passive-recon

Nicht-invasive Schwachstellen-Reconnaissance für IPs und Domains.
Read-only / low-impact: nur einfache GET-Requests und einzelne TCP-Connects.
**Kein** Brute-Force, **kein** Fuzzing, **keine** Exploits, **keine** schreibenden Zugriffe.

Nur Python-Standardlibrary — keine Installation von Dependencies nötig (Python ≥ 3.9).

> ⚠️ Nur gegen Systeme einsetzen, für die eine **schriftliche Testfreigabe** (Scope/Auftrag) vorliegt.

## Was wird geprüft

| Check | Kategorie | Methode |
|-------|-----------|---------|
| WordPress-Erkennung + Version | `wordpress` | meta-generator, `readme.html`, RSS-Feed |
| WP User-Enumeration | `wordpress` | `/wp-json/wp/v2/users` + `/?author=N` (N klein) |
| XML-RPC aktiv | `wordpress` | GET `/xmlrpc.php` |
| CVE-Abgleich Core & Plugins | `wordpress` | WPScan API (Key nötig) |
| Directory Listing | `directory-listing` | "Index of /"-Erkennung auf kleiner Pfadliste + robots-Pfaden |
| Interessante robots.txt-Einträge | `robots` | Filtert Standard-Einträge raus, hebt „juicy" Pfade hervor |
| HTTP Basic/Digest-Auth Popups | `basic-auth` | 401 + `WWW-Authenticate` |
| Offene FTP-/SQL-/DB-Ports | `ports` | TCP-Connect + Banner-Grab (kein Login) |
| **Banner → CVE** | `cve` | Erkennt Produkt+Version im Banner (HTTP `Server`/`X-Powered-By`, FTP, MySQL/MariaDB…), mappt auf CPE und gibt via **NVD-API** die passenden CVEs aus (nach CVSS sortiert) |
| Security-Header / Banner | `headers` | aus der Root-Antwort |
| Voll-passiv (optional) | `shodan` | Shodan Host-Lookup, **kein** Kontakt zum Ziel |

Erkannte Banner für CVE-Abgleich: Apache httpd, nginx, OpenSSH, OpenSSL, PHP,
Microsoft IIS, lighttpd, Exim, ProFTPD, vsftpd, Pure-FTPd, MySQL, MariaDB.

Geprüfte Ports: 21 (FTP), 3306 (MySQL/MariaDB), 5432 (PostgreSQL), 1433 (MSSQL),
1521 (Oracle), 27017 (MongoDB), 6379 (Redis), 5984 (CouchDB), 9200 (Elasticsearch),
11211 (Memcached). Anpassbar über `--ports`.

## Web-UI (lokal hosten)

Schönes Dark-UI im Browser, das denselben Scanner nutzt und Ergebnisse pro Ziel
live streamt. Läuft nur lokal (`127.0.0.1`), keine externen Dependencies.

```bash
cd passive-recon
python3 web_app.py            # -> http://127.0.0.1:8787
python3 web_app.py --open     # startet + öffnet den Browser automatisch
python3 web_app.py --port 9000
```

Auf macOS alternativ per Doppelklick: **`start-web.command`**.

Dann im Browser `http://127.0.0.1:8787` öffnen: Ziele eintragen, Testfreigabe
bestätigen, „Scan starten". API-Keys optional unter „Erweiterte Optionen"
(leer = ENV / `config.json` des Servers). Ergebnisse werden ausschließlich lokal
verarbeitet und können per „Als JSON exportieren" gespeichert werden.

## Nutzung (CLI)

```bash
# Einzelziel
python3 passive_recon.py example.com

# Mehrere Ziele + IP
python3 passive_recon.py example.com 203.0.113.10

# Zielliste aus Datei
python3 passive_recon.py -f targets.txt

# WPScan-Key setzen (3 Wege möglich)
export WPSCAN_API_KEY="dein_key"
python3 passive_recon.py example.com
#   ...oder
python3 passive_recon.py --wpscan-api-key dein_key example.com
#   ...oder cp config.example.json config.json  und dort eintragen

# Ergebnis als JSON exportieren
python3 passive_recon.py example.com -o ergebnis.json

# Voll passiv (kein Kontakt zum Ziel, nur Shodan-Daten)
python3 passive_recon.py --passive-only --shodan-api-key dein_key 203.0.113.10

# In Skripten/Pipelines ohne Rückfrage (nur mit Auftrag!)
python3 passive_recon.py -y example.com
```

## API-Key hinterlegen

Priorität: `--wpscan-api-key` / `--shodan-api-key` → Umgebungsvariable
`WPSCAN_API_KEY` / `SHODAN_API_KEY` → `config.json`.

`config.json` wird gesucht in: `--config <pfad>` → aktuelles Verzeichnis →
`~/.config/passive-recon/config.json`.

```bash
cp config.example.json config.json
# WPScan-Key kostenlos: https://wpscan.com/api  (25 Requests/Tag im Free-Tier)
# NVD-Key kostenlos:    https://nvd.nist.gov/developers/request-an-api-key
#   (ohne NVD-Key funktioniert der CVE-Abgleich auch, ist nur langsamer:
#    5 statt 50 Requests / 30 s → ca. 6 s Wartezeit pro Produkt-Lookup)
```

Banner-CVE-Abgleich abschalten: `--no-cve`. Anzahl CVEs pro Produkt: `--max-cves N`.

## Hinweis zu „passiv"

Echte WP-Enumeration, Directory-Listing, robots.txt und Port-Status setzen einen
minimalen Kontakt mit dem Ziel voraus. Das Tool hält diesen so gering wie möglich
(einzelne GETs, ein TCP-Connect pro Port, keine Wiederholungen, keine Payloads).
Wer **null** Kontakt will, nutzt `--passive-only` (Shodan).

Für einen vollen, aktiven Vuln-Scan (OpenVAS/Greenbone, Nessus, Nuclei) ist dieses
Tool bewusst nicht gedacht — das wäre invasiv.
