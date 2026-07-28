#!/usr/bin/env python3
"""
passive-recon — Nicht-invasive Schwachstellen-Reconnaissance fuer IPs & Domains.

Ziel: Read-only / low-impact Checks. KEIN Brute-Force, KEIN Fuzzing, KEINE
Exploits, KEINE schreibenden Zugriffe. Nur einfache GET-Requests und einzelne
TCP-Connects (Banner-Grab). Optional voll-passiv ueber Shodan (kein Kontakt zum Ziel).

Nur mit Python-Standardlibrary (keine externen Dependencies).

WICHTIG: Nur gegen Systeme einsetzen, fuer die eine ausdrueckliche schriftliche
Testfreigabe (Scope/Auftrag) vorliegt.
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from html.parser import HTMLParser
from typing import Optional

# --------------------------------------------------------------------------- #
# Konfiguration / Defaults
# --------------------------------------------------------------------------- #

DEFAULT_UA = "passive-recon/1.0 (+authorized security assessment)"
DEFAULT_TIMEOUT = 8.0
DEFAULT_USER_ENUM_MAX = 3          # /?author=1..N  (klein halten = nicht-invasiv)
DEFAULT_PORT_TIMEOUT = 3.0
WPSCAN_API = "https://wpscan.com/api/v3"
SHODAN_API = "https://api.shodan.io"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_MAX_CVES = 10              # max. CVEs pro erkanntem Produkt/Banner

# SQL-/DB- und FTP-Ports die geprueft werden (single TCP connect, kein Login)
DB_PORTS = {
    21:    "FTP",
    3306:  "MySQL/MariaDB",
    5432:  "PostgreSQL",
    1433:  "MSSQL",
    1521:  "Oracle DB",
    27017: "MongoDB",
    6379:  "Redis",
    5984:  "CouchDB",
    9200:  "Elasticsearch",
    11211: "Memcached",
}

# Kleine, gezielte Liste haeufiger Verzeichnisse fuer Directory-Listing-Check.
# Bewusst klein gehalten (nicht-invasiv, kein Fuzzing).
DIR_CANDIDATES = [
    "/", "/wp-content/uploads/", "/wp-content/", "/wp-includes/",
    "/uploads/", "/backup/", "/backups/", "/files/", "/images/",
    "/img/", "/assets/", "/tmp/", "/old/", "/test/", "/.git/",
]

# robots.txt Disallow-Eintraege die als "langweilig/Standard" gelten und NICHT
# gemeldet werden. Alles andere wird als interessant markiert.
ROBOTS_BORING = [
    "/wp-admin/", "/wp-includes/", "/cgi-bin/", "/wp-login.php",
    "/xmlrpc.php", "/", "/*?", "/*?*", "/search/", "/?s=",
    "/feed/", "/comments/", "/trackback/", "/author/",
]

# Schluesselwoerter die einen robots.txt-Pfad besonders interessant machen.
ROBOTS_JUICY = [
    "admin", "backup", "bak", "old", "config", "conf", "db", "sql",
    "dump", "secret", "private", "priv", "internal", "intern", "test",
    "dev", "staging", "stage", "api", "token", "key", "cred", "password",
    "passwd", "log", "logs", "phpmyadmin", "pma", "adminer", "install",
    "setup", "upload", "tmp", "temp", ".git", ".env", ".svn", "vault",
    "cms", "portal", "restricted", "hidden", "beta", "old_site",
]

# --------------------------------------------------------------------------- #
# Farben
# --------------------------------------------------------------------------- #

class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"

    _enabled = True

    @classmethod
    def wrap(cls, s: str, color: str) -> str:
        if not cls._enabled:
            return s
        return f"{color}{s}{cls.RESET}"


def sev_color(sev: str) -> str:
    return {
        "critical": C.RED, "high": C.RED, "medium": C.YELLOW,
        "low": C.CYAN, "info": C.DIM,
    }.get(sev, C.RESET)


# --------------------------------------------------------------------------- #
# Findings-Datenmodell
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    category: str            # z.B. "wordpress", "directory-listing", "ports"
    title: str
    severity: str = "info"   # info|low|medium|high|critical
    detail: str = ""
    evidence: str = ""       # URL / Pfad / Banner

    def line(self) -> str:
        tag = f"[{self.severity.upper()}]"
        tag = C.wrap(f"{tag:<10}", sev_color(self.severity))
        head = C.wrap(self.title, C.BOLD)
        s = f"  {tag} {head}"
        if self.evidence:
            s += "\n" + C.wrap(f"             -> {self.evidence}", C.CYAN)
        if self.detail:
            s += "\n" + C.wrap(f"             {self.detail}", C.DIM)
        return s


@dataclass
class TargetResult:
    target: str
    resolved_ip: Optional[str] = None
    base_url: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)


# --------------------------------------------------------------------------- #
# HTTP-Helfer (nur GET, folgt Redirects manuell begrenzt)
# --------------------------------------------------------------------------- #

@dataclass
class HttpResponse:
    status: int
    headers: dict
    body: str
    final_url: str


_UNVERIFIED_CTX = ssl.create_default_context()
_UNVERIFIED_CTX.check_hostname = False
_UNVERIFIED_CTX.verify_mode = ssl.CERT_NONE


def http_get(url: str, timeout: float, ua: str,
             max_body: int = 400_000, allow_redirects: bool = True,
             extra_headers: Optional[dict] = None) -> Optional[HttpResponse]:
    """Ein einzelner, harmloser GET. Gibt None bei Netzwerkfehler zurueck."""
    headers = {"User-Agent": ua, "Accept": "*/*", "Connection": "close"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers, method="GET")
    handlers = []
    if not allow_redirects:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_UNVERIFIED_CTX), *handlers
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(max_body)
            body = raw.decode(resp.headers.get_content_charset() or "utf-8",
                              errors="replace")
            return HttpResponse(resp.status, dict(resp.headers), body,
                                resp.geturl())
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(max_body)
            body = raw.decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return HttpResponse(e.code, dict(e.headers or {}), body, url)
    except (urllib.error.URLError, socket.timeout, ssl.SSLError,
            ConnectionError, OSError):
        return None
    except Exception:
        return None


def pick_base_url(target: str, timeout: float, ua: str) -> Optional[HttpResponse]:
    """Ermittelt eine erreichbare Basis-URL (https bevorzugt)."""
    if target.startswith("http://") or target.startswith("https://"):
        candidates = [target]
    else:
        candidates = [f"https://{target}", f"http://{target}"]
    for url in candidates:
        r = http_get(url, timeout, ua)
        if r is not None:
            return r
    return None


# --------------------------------------------------------------------------- #
# WordPress-Erkennung & Version
# --------------------------------------------------------------------------- #

_META_GEN_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([0-9.]+)?',
    re.I)
_WP_HINT_RE = re.compile(r'wp-content|wp-includes|/wp-json|wp-emoji', re.I)
_PLUGIN_RE = re.compile(r'wp-content/plugins/([a-z0-9\-_]+)', re.I)
_THEME_RE = re.compile(r'wp-content/themes/([a-z0-9\-_]+)', re.I)
_README_VER_RE = re.compile(r'Version\s+([0-9.]+)', re.I)
_RSS_GEN_RE = re.compile(r'<generator>[^<]*wordpress\.org/\?v=([0-9.]+)', re.I)


def detect_wordpress(base: HttpResponse, base_url: str, timeout: float,
                     ua: str) -> tuple[bool, Optional[str], set, set]:
    """Gibt (is_wp, version, plugins, themes) zurueck."""
    body = base.body
    is_wp = bool(_WP_HINT_RE.search(body)) or bool(_META_GEN_RE.search(body))
    version = None

    m = _META_GEN_RE.search(body)
    if m and m.group(1):
        version = m.group(1)

    plugins = set(_PLUGIN_RE.findall(body))
    themes = set(_THEME_RE.findall(body))

    # readme.html (nicht-invasiv, oeffentliche Datei) fuer Version
    if is_wp and not version:
        r = http_get(base_url.rstrip("/") + "/readme.html", timeout, ua)
        if r and r.status == 200 and "wordpress" in r.body.lower():
            mm = _README_VER_RE.search(r.body)
            if mm:
                version = mm.group(1)

    # RSS-Feed generator als Fallback
    if is_wp and not version:
        r = http_get(base_url.rstrip("/") + "/feed/", timeout, ua)
        if r and r.status == 200:
            mm = _RSS_GEN_RE.search(r.body)
            if mm:
                version = mm.group(1)

    return is_wp, version, plugins, themes


def check_user_enum(base_url: str, timeout: float, ua: str,
                    max_ids: int) -> list[Finding]:
    findings: list[Finding] = []
    root = base_url.rstrip("/")

    # 1) REST-API: /wp-json/wp/v2/users  (haeufig offen)
    r = http_get(root + "/wp-json/wp/v2/users", timeout, ua)
    if r and r.status == 200 and r.body.strip().startswith("["):
        try:
            users = json.loads(r.body)
            names = [u.get("slug") or u.get("name") for u in users if isinstance(u, dict)]
            names = [n for n in names if n]
            if names:
                findings.append(Finding(
                    "wordpress", "WP User-Enumeration via REST-API moeglich",
                    "high",
                    detail="Benutzer: " + ", ".join(names[:20]),
                    evidence=root + "/wp-json/wp/v2/users"))
        except json.JSONDecodeError:
            pass

    # 2) /?author=N  -> Redirect auf /author/<login>/
    found_authors = {}
    for i in range(1, max_ids + 1):
        r = http_get(f"{root}/?author={i}", timeout, ua, allow_redirects=False)
        if not r:
            continue
        loc = r.headers.get("Location", "")
        if r.status in (301, 302) and "/author/" in loc:
            slug = loc.rstrip("/").split("/author/")[-1].split("/")[0]
            if slug:
                found_authors[i] = slug
        elif r.status == 200:
            m = re.search(r'/author/([a-z0-9\-_.]+)/', r.body, re.I)
            if m:
                found_authors[i] = m.group(1)
    if found_authors:
        listing = ", ".join(f"{k}:{v}" for k, v in found_authors.items())
        findings.append(Finding(
            "wordpress", "WP User-Enumeration via ?author= moeglich", "medium",
            detail="ID:Login  -> " + listing,
            evidence=f"{root}/?author=1"))
    return findings


def check_xmlrpc(base_url: str, timeout: float, ua: str) -> list[Finding]:
    root = base_url.rstrip("/")
    r = http_get(root + "/xmlrpc.php", timeout, ua)
    if r and r.status in (200, 405) and (
            "XML-RPC server accepts POST requests only" in r.body
            or "xmlrpc" in r.body.lower() and r.status == 405):
        return [Finding(
            "wordpress", "XML-RPC aktiviert (xmlrpc.php erreichbar)", "medium",
            detail="Kann fuer Brute-Force/Pingback-DDoS/Amplification missbraucht "
                   "werden. Empfehlung: deaktivieren/beschraenken.",
            evidence=root + "/xmlrpc.php")]
    return []


# --------------------------------------------------------------------------- #
# WPScan API
# --------------------------------------------------------------------------- #

def wpscan_lookup(kind: str, slug_or_version: str, api_key: str,
                  timeout: float) -> Optional[dict]:
    """kind: 'wordpresses' | 'plugins' | 'themes'."""
    if not api_key:
        return None
    ver = slug_or_version.replace(".", "") if kind == "wordpresses" else slug_or_version
    url = f"{WPSCAN_API}/{kind}/{ver}"
    r = http_get(url, timeout, DEFAULT_UA,
                 extra_headers={"Authorization": f"Token token={api_key}"})
    if not r:
        return None
    if r.status == 429:
        return {"__error__": "WPScan API Rate-Limit erreicht (429)"}
    if r.status == 401:
        return {"__error__": "WPScan API Key ungueltig (401)"}
    if r.status != 200:
        return None
    try:
        return json.loads(r.body)
    except json.JSONDecodeError:
        return None


def wpscan_findings(is_wp: bool, version: Optional[str], plugins: set,
                    api_key: str, timeout: float) -> list[Finding]:
    findings: list[Finding] = []
    if not api_key:
        if is_wp:
            findings.append(Finding(
                "wordpress", "WPScan-Abgleich uebersprungen (kein API-Key)",
                "info",
                detail="Setze WPSCAN_API_KEY oder --wpscan-api-key fuer "
                       "Versions-/Plugin-CVE-Abgleich."))
        return findings

    def _emit(data: dict, label: str):
        if not data:
            return
        if "__error__" in data:
            findings.append(Finding("wordpress", data["__error__"], "info"))
            return
        for _key, entry in data.items():
            vulns = entry.get("vulnerabilities", []) if isinstance(entry, dict) else []
            for v in vulns:
                title = v.get("title", "Unbekannte Schwachstelle")
                refs = v.get("references", {}) or {}
                cve = ""
                if refs.get("cve"):
                    cve = "CVE-" + ", CVE-".join(refs["cve"])
                findings.append(Finding(
                    "wordpress", f"{label}: {title}", "high",
                    detail=cve, evidence=refs.get("url", [""])[0] if refs.get("url") else ""))

    if version:
        _emit(wpscan_lookup("wordpresses", version, api_key, timeout),
              f"WP-Core {version}")
    for slug in sorted(plugins)[:15]:   # begrenzen (API-Quota schonen)
        _emit(wpscan_lookup("plugins", slug, api_key, timeout),
              f"Plugin {slug}")
    return findings


# --------------------------------------------------------------------------- #
# Directory Listing
# --------------------------------------------------------------------------- #

_INDEX_OF_RE = re.compile(
    r'<title>\s*Index of /|<h1>\s*Index of /|Directory listing for|'
    r'\[To Parent Directory\]', re.I)


def check_directory_listing(base_url: str, extra_paths: list[str],
                            timeout: float, ua: str) -> list[Finding]:
    findings: list[Finding] = []
    root = base_url.rstrip("/")
    seen = set()
    paths = DIR_CANDIDATES + [p for p in extra_paths if p.endswith("/")]
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        url = root + path
        r = http_get(url, timeout, ua)
        if r and r.status == 200 and _INDEX_OF_RE.search(r.body):
            findings.append(Finding(
                "directory-listing", f"Directory Listing offen: {path}",
                "medium", evidence=url))
    return findings


# --------------------------------------------------------------------------- #
# robots.txt
# --------------------------------------------------------------------------- #

def check_robots(base_url: str, timeout: float, ua: str) -> tuple[list[Finding], list[str]]:
    root = base_url.rstrip("/")
    r = http_get(root + "/robots.txt", timeout, ua)
    findings: list[Finding] = []
    disallowed: list[str] = []
    if not r or r.status != 200 or "Disallow" not in r.body and "Allow" not in r.body:
        return findings, disallowed

    for line in r.body.splitlines():
        line = line.strip()
        if line.lower().startswith(("disallow:", "allow:")):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)

    interesting = []
    for path in disallowed:
        low = path.lower()
        if any(path == b or low == b for b in ROBOTS_BORING):
            continue
        if any(j in low for j in ROBOTS_JUICY) or (
                path not in ROBOTS_BORING and not low.startswith("/wp-")):
            interesting.append(path)

    # de-dup, priorisieren
    interesting = list(dict.fromkeys(interesting))
    for path in interesting:
        low = path.lower()
        sev = "medium" if any(j in low for j in ROBOTS_JUICY) else "low"
        findings.append(Finding(
            "robots", f"Interessanter robots.txt Eintrag: {path}", sev,
            evidence=root + path.replace("*", "")))
    return findings, disallowed


# --------------------------------------------------------------------------- #
# Basic-Auth Popups (401 + WWW-Authenticate: Basic)
# --------------------------------------------------------------------------- #

BASIC_AUTH_PATHS = ["/", "/wp-admin/", "/admin/", "/login/", "/manager/",
                    "/phpmyadmin/", "/.git/", "/backup/", "/private/"]


def check_basic_auth(base_url: str, timeout: float, ua: str) -> list[Finding]:
    findings: list[Finding] = []
    root = base_url.rstrip("/")
    seen = set()
    for path in BASIC_AUTH_PATHS:
        url = root + path
        if url in seen:
            continue
        seen.add(url)
        r = http_get(url, timeout, ua, allow_redirects=False)
        if not r:
            continue
        if r.status == 401:
            www = r.headers.get("WWW-Authenticate", "")
            scheme = www.split()[0] if www else "?"
            realm = ""
            m = re.search(r'realm=["\']?([^"\',]+)', www)
            if m:
                realm = m.group(1)
            if scheme.lower() in ("basic", "digest", "ntlm", "negotiate", "?"):
                findings.append(Finding(
                    "basic-auth",
                    f"HTTP-Auth Popup ({scheme}) auf {path}", "low",
                    detail=f"realm: {realm}" if realm else "",
                    evidence=url))
    return findings


# --------------------------------------------------------------------------- #
# Security-Header (Bonus, rein passiv aus der Root-Antwort)
# --------------------------------------------------------------------------- #

def check_headers(base: HttpResponse, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    h = {k.lower(): v for k, v in base.headers.items()}
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    banner = ", ".join(x for x in [server, powered] if x)
    if banner:
        findings.append(Finding(
            "headers", "Server-/Technologie-Banner offengelegt", "info",
            detail=banner, evidence=base_url))
    missing = []
    for hdr in ("strict-transport-security", "content-security-policy",
                "x-frame-options", "x-content-type-options"):
        if hdr not in h:
            missing.append(hdr)
    if missing:
        findings.append(Finding(
            "headers", "Fehlende Security-Header", "low",
            detail=", ".join(missing)))
    return findings


# --------------------------------------------------------------------------- #
# Port-Checks (TCP connect + Banner). Nicht-invasiv: 1 Connect, kein Login.
# --------------------------------------------------------------------------- #

def grab_banner(ip: str, port: int, timeout: float) -> Optional[str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Fuer manche Dienste erst nach Prompt/Probe. FTP/Redis liefern
            # ungefragt ein Banner; MySQL sendet Handshake sofort.
            try:
                data = s.recv(256)
            except socket.timeout:
                data = b""
            return data.decode("latin-1", errors="replace").strip() or None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def check_ports(ip: str, ports: dict, timeout: float,
                max_workers: int = 8) -> tuple[list[Finding], list[tuple]]:
    """Gibt (findings, banners) zurueck. banners: [(banner, evidence, hint)]."""
    findings: list[Finding] = []
    banners: list[tuple] = []

    def _probe(item):
        port, name = item
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                pass
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        banner = grab_banner(ip, port, timeout)
        return (port, name, banner)

    with futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for res in ex.map(_probe, ports.items()):
            if res is None:
                continue
            port, name, banner = res
            sev = "high" if port in (3306, 5432, 1433, 1521, 27017, 6379,
                                     9200, 11211, 5984) else "medium"
            detail = f"Banner: {banner}" if banner else "Port offen (kein Banner)"
            findings.append(Finding(
                "ports", f"Offener Port {port}/tcp ({name})", sev,
                detail=detail, evidence=f"{ip}:{port}"))
            if banner:
                banners.append((banner, f"{ip}:{port}", name))
    return findings, banners


def resolve_ip(target: str) -> Optional[str]:
    host = target
    for pref in ("https://", "http://"):
        if host.startswith(pref):
            host = host[len(pref):]
    host = host.split("/")[0].split(":")[0]
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return None


# --------------------------------------------------------------------------- #
# Banner -> CPE -> CVE (NVD API)
# --------------------------------------------------------------------------- #

# Jeder Eintrag: (regex mit Versions-Gruppe, Anzeige-Name, [CPE-Kandidaten]).
# CPE-Kandidaten werden der Reihe nach abgefragt; der erste Treffer gewinnt.
BANNER_MATCHERS = [
    (re.compile(r'Apache/(\d+\.\d+(?:\.\d+)?)', re.I),
     "Apache httpd {v}", ["cpe:2.3:a:apache:http_server:{v}"]),
    (re.compile(r'nginx/(\d+\.\d+(?:\.\d+)?)', re.I),
     "nginx {v}", ["cpe:2.3:a:f5:nginx:{v}", "cpe:2.3:a:nginx:nginx:{v}"]),
    (re.compile(r'OpenSSH[_/](\d+\.\d+(?:\.\d+)?)(?:p\d+)?', re.I),
     "OpenSSH {v}", ["cpe:2.3:a:openbsd:openssh:{v}"]),
    (re.compile(r'OpenSSL/(\d+\.\d+\.\d+[a-z]?)', re.I),
     "OpenSSL {v}", ["cpe:2.3:a:openssl:openssl:{v}"]),
    (re.compile(r'PHP/(\d+\.\d+\.\d+)', re.I),
     "PHP {v}", ["cpe:2.3:a:php:php:{v}"]),
    (re.compile(r'ProFTPD (\d+\.\d+\.\d+)', re.I),
     "ProFTPD {v}", ["cpe:2.3:a:proftpd:proftpd:{v}"]),
    (re.compile(r'vsftpd (\d+\.\d+\.\d+)', re.I),
     "vsftpd {v}", ["cpe:2.3:a:vsftpd_project:vsftpd:{v}",
                    "cpe:2.3:a:beasts:vsftpd:{v}"]),
    (re.compile(r'Pure-FTPd[^0-9]*(\d+\.\d+\.\d+)', re.I),
     "Pure-FTPd {v}", ["cpe:2.3:a:pureftpd:pure-ftpd:{v}"]),
    (re.compile(r'Microsoft-IIS/(\d+\.\d+)', re.I),
     "Microsoft IIS {v}", ["cpe:2.3:a:microsoft:internet_information_services:{v}"]),
    (re.compile(r'\bExim (\d+\.\d+(?:\.\d+)?)', re.I),
     "Exim {v}", ["cpe:2.3:a:exim:exim:{v}"]),
    (re.compile(r'lighttpd/(\d+\.\d+\.\d+)', re.I),
     "lighttpd {v}", ["cpe:2.3:a:lighttpd:lighttpd:{v}"]),
]


def parse_banner(banner: str, hint: str = "") -> list[tuple[str, list[str]]]:
    """Extrahiert (Anzeige-Name, [CPE-Kandidaten]) aus einem Banner-String."""
    out: list[tuple[str, list[str]]] = []
    seen: set[str] = set()

    for rx, name_fmt, cpe_tpls in BANNER_MATCHERS:
        m = rx.search(banner)
        if not m:
            continue
        v = m.group(1)
        name = name_fmt.format(v=v)
        if name in seen:
            continue
        seen.add(name)
        out.append((name, [t.format(v=v) for t in cpe_tpls]))

    # DB-Handshakes (Version steht im Klartext, aber ohne Produktnamen)
    low_hint = hint.lower()
    if "mysql" in low_hint or "mariadb" in low_hint or "mariadb" in banner.lower():
        mm = re.search(r'(\d+\.\d+\.\d+)-MariaDB', banner) \
            or re.search(r'5\.5\.5-(\d+\.\d+\.\d+)', banner)
        if mm and f"MariaDB {mm.group(1)}" not in seen:
            out.append((f"MariaDB {mm.group(1)}",
                        [f"cpe:2.3:a:mariadb:mariadb:{mm.group(1)}"]))
        elif not mm:
            mv = re.search(r'(\d+\.\d+\.\d+)', banner)
            if mv:
                out.append((f"MySQL {mv.group(1)}",
                            [f"cpe:2.3:a:oracle:mysql:{mv.group(1)}"]))
    return out


def _cvss_of(cve: dict) -> tuple[Optional[float], str]:
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            score = data.get("baseScore")
            sev = (data.get("baseSeverity")
                   or arr[0].get("baseSeverity") or "").lower()
            if not sev and isinstance(score, (int, float)):
                sev = ("critical" if score >= 9 else "high" if score >= 7
                       else "medium" if score >= 4 else "low")
            return score, (sev or "medium")
    return None, "medium"


def _first_desc(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "").strip()
    descs = cve.get("descriptions", [])
    return descs[0].get("value", "").strip() if descs else ""


class NvdClient:
    """Fragt die NVD-API ab (mit Throttling, Cache). Kein Key noetig, aber
    empfohlen (5 vs. 50 Requests/30s)."""

    def __init__(self, api_key: str, timeout: float,
                 max_cves: int = DEFAULT_MAX_CVES, enabled: bool = True):
        self.api_key = api_key
        self.timeout = timeout
        self.max_cves = max_cves
        self.enabled = enabled
        self._last = 0.0
        self._cache: dict[str, list] = {}

    def _throttle(self) -> None:
        gap = 0.8 if self.api_key else 6.5
        wait = gap - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def _query(self, cpe: str) -> list:
        if cpe in self._cache:
            return self._cache[cpe]
        self._throttle()
        url = (NVD_API + "?virtualMatchString="
               + urllib.parse.quote(cpe) + "&resultsPerPage=200")
        headers = {"apiKey": self.api_key} if self.api_key else {}
        r = http_get(url, max(self.timeout, 20.0), DEFAULT_UA,
                     max_body=6_000_000, extra_headers=headers)
        cves: list = []
        if r and r.status == 200:
            try:
                data = json.loads(r.body)
                cves = [it.get("cve", {}) for it in data.get("vulnerabilities", [])]
            except json.JSONDecodeError:
                pass
        self._cache[cpe] = cves
        return cves

    def cve_findings(self, banner: str, evidence: str,
                     hint: str = "") -> list[Finding]:
        if not self.enabled or not banner:
            return []
        findings: list[Finding] = []
        for name, candidates in parse_banner(banner, hint):
            cves, used = [], None
            for cpe in candidates:
                cves = self._query(cpe)
                if cves:
                    used = cpe
                    break
            if not cves:
                continue
            scored = []
            for c in cves:
                score, sev = _cvss_of(c)
                scored.append((score or 0.0, c.get("id", ""), sev, _first_desc(c)))
            scored.sort(key=lambda x: (-x[0], x[1]))
            top = scored[:self.max_cves]
            for score, cid, sev, desc in top:
                sc = f" (CVSS {score})" if score else ""
                findings.append(Finding(
                    "cve", f"{name}: {cid}{sc}", sev,
                    detail=desc[:180],
                    evidence=f"https://nvd.nist.gov/vuln/detail/{cid}  [{evidence}]"))
            if len(scored) > len(top):
                findings.append(Finding(
                    "cve", f"{name}: +{len(scored) - len(top)} weitere CVEs",
                    "info", detail=f"gekuerzt (--max-cves erhoehen); CPE {used}"))
        return findings


# --------------------------------------------------------------------------- #
# Shodan (voll-passiv, optional)
# --------------------------------------------------------------------------- #

def shodan_lookup(ip: str, api_key: str, timeout: float) -> list[Finding]:
    findings: list[Finding] = []
    url = f"{SHODAN_API}/shodan/host/{ip}?key={api_key}"
    r = http_get(url, timeout, DEFAULT_UA)
    if not r or r.status != 200:
        if r and r.status == 401:
            findings.append(Finding("shodan", "Shodan API Key ungueltig", "info"))
        return findings
    try:
        data = json.loads(r.body)
    except json.JSONDecodeError:
        return findings
    for svc in data.get("data", []):
        port = svc.get("port")
        product = svc.get("product", "")
        name = DB_PORTS.get(port, svc.get("_shodan", {}).get("module", ""))
        sev = "high" if port in DB_PORTS and DB_PORTS[port] != "FTP" else "medium"
        findings.append(Finding(
            "shodan", f"[Shodan] Port {port}/tcp {name} {product}".strip(),
            sev, evidence=f"{ip}:{port}"))
    for vuln in data.get("vulns", []):
        findings.append(Finding("shodan", f"[Shodan] {vuln}", "high"))
    return findings


# --------------------------------------------------------------------------- #
# Scan-Orchestrierung pro Ziel
# --------------------------------------------------------------------------- #

def scan_target(target: str, cfg: dict) -> TargetResult:
    res = TargetResult(target=target)
    timeout = cfg["timeout"]
    ua = cfg["ua"]

    res.resolved_ip = resolve_ip(target)

    # ---- Voll-passiver Modus: nur Shodan ----
    if cfg.get("passive_only"):
        if res.resolved_ip and cfg.get("shodan_api_key"):
            for f in shodan_lookup(res.resolved_ip, cfg["shodan_api_key"], timeout):
                res.add(f)
        else:
            res.errors.append("passive-only: benoetigt aufloesbare IP + Shodan-Key")
        return res

    # ---- Port-Checks ----
    banners_for_cve: list[tuple] = []   # (banner, evidence, hint)

    if res.resolved_ip and not cfg.get("no_ports"):
        port_findings, port_banners = check_ports(
            res.resolved_ip, cfg["ports"], cfg["port_timeout"])
        for f in port_findings:
            res.add(f)
        banners_for_cve += port_banners

    # ---- Optional zusaetzlich Shodan ----
    if cfg.get("shodan_api_key") and res.resolved_ip:
        for f in shodan_lookup(res.resolved_ip, cfg["shodan_api_key"], timeout):
            res.add(f)

    # ---- HTTP-basierte Checks ----
    if not cfg.get("no_http"):
        base = pick_base_url(target, timeout, ua)
        if base is None:
            res.errors.append("Kein HTTP(S) erreichbar")
            return res
        base_url = base.final_url
        res.base_url = base_url

        for f in check_headers(base, base_url):
            res.add(f)

        # HTTP-Banner (Server / X-Powered-By) fuer CVE-Abgleich sammeln
        _h = {k.lower(): v for k, v in base.headers.items()}
        for hk in ("server", "x-powered-by"):
            if _h.get(hk):
                banners_for_cve.append((_h[hk], base_url, "http"))

        robots_findings, disallowed = check_robots(base_url, timeout, ua)
        for f in robots_findings:
            res.add(f)

        for f in check_basic_auth(base_url, timeout, ua):
            res.add(f)

        for f in check_directory_listing(base_url, disallowed, timeout, ua):
            res.add(f)

        is_wp, version, plugins, themes = detect_wordpress(base, base_url, timeout, ua)
        if is_wp:
            v = f" (Version {version})" if version else " (Version unbekannt)"
            res.add(Finding("wordpress", f"WordPress erkannt{v}", "info",
                            detail=(f"Plugins: {', '.join(sorted(plugins))}"
                                    if plugins else ""),
                            evidence=base_url))
            for f in check_xmlrpc(base_url, timeout, ua):
                res.add(f)
            for f in check_user_enum(base_url, timeout, ua, cfg["user_enum_max"]):
                res.add(f)
            for f in wpscan_findings(is_wp, version, plugins,
                                     cfg.get("wpscan_api_key", ""), timeout):
                res.add(f)

    # ---- Banner -> CVE (NVD) ----
    nvd: Optional[NvdClient] = cfg.get("nvd_client")
    if nvd and nvd.enabled and banners_for_cve:
        seen_cve: set[str] = set()
        for banner, evidence, hint in banners_for_cve:
            for f in nvd.cve_findings(banner, evidence, hint):
                key = f.evidence or f.title
                if key in seen_cve:
                    continue
                seen_cve.add(key)
                res.add(f)
    return res


# --------------------------------------------------------------------------- #
# Ausgabe
# --------------------------------------------------------------------------- #

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def print_result(res: TargetResult) -> None:
    print()
    print(C.wrap("=" * 70, C.BLUE))
    ip = f"  ({res.resolved_ip})" if res.resolved_ip else ""
    print(C.wrap(f" ZIEL: {res.target}{ip}", C.BOLD))
    if res.base_url:
        print(C.wrap(f" URL:  {res.base_url}", C.DIM))
    print(C.wrap("=" * 70, C.BLUE))

    if res.errors:
        for e in res.errors:
            print(C.wrap(f"  [!] {e}", C.YELLOW))

    if not res.findings:
        print(C.wrap("  Keine Findings.", C.DIM))
        return

    findings = sorted(res.findings, key=lambda f: (SEV_ORDER.get(f.severity, 9),
                                                   f.category))
    for f in findings:
        print(f.line())

    # Zusammenfassung
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "  ".join(
        C.wrap(f"{sev}:{counts[sev]}", sev_color(sev))
        for sev in ["critical", "high", "medium", "low", "info"]
        if sev in counts)
    print(C.wrap("  " + "-" * 66, C.DIM))
    print("  " + summary)


# --------------------------------------------------------------------------- #
# Config laden
# --------------------------------------------------------------------------- #

def load_config_file(path: Optional[str]) -> dict:
    candidates = []
    if path:
        candidates.append(path)
    candidates += [
        os.path.join(os.getcwd(), "config.json"),
        os.path.expanduser("~/.config/passive-recon/config.json"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            try:
                with open(c, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except (json.JSONDecodeError, OSError):
                continue
    return {}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="passive-recon",
        description="Nicht-invasive Schwachstellen-Reconnaissance (read-only).",
        epilog="Nur mit ausdruecklicher Testfreigabe einsetzen.")
    p.add_argument("targets", nargs="*", help="IPs und/oder Domains")
    p.add_argument("-f", "--file", help="Datei mit Zielen (eine pro Zeile)")
    p.add_argument("-o", "--output", help="Ergebnisse als JSON in Datei schreiben")
    p.add_argument("--config", help="Pfad zur config.json")
    p.add_argument("--wpscan-api-key", help="WPScan API Key (oder WPSCAN_API_KEY / config.json)")
    p.add_argument("--shodan-api-key", help="Shodan API Key (oder SHODAN_API_KEY / config.json)")
    p.add_argument("--nvd-api-key", help="NVD API Key fuer Banner-CVE-Abgleich "
                   "(oder NVD_API_KEY / config.json; optional, aber schneller)")
    p.add_argument("--no-cve", action="store_true",
                   help="Banner-CVE-Abgleich (NVD) deaktivieren")
    p.add_argument("--max-cves", type=int, default=DEFAULT_MAX_CVES,
                   help="Max. CVEs pro erkanntem Produkt/Banner")
    p.add_argument("--passive-only", action="store_true",
                   help="Voll passiv: kein Kontakt zum Ziel, nur Shodan")
    p.add_argument("--no-ports", action="store_true", help="Port-Checks ueberspringen")
    p.add_argument("--no-http", action="store_true", help="HTTP-Checks ueberspringen")
    p.add_argument("--ports", help="Kommagetrennte Portliste ueberschreiben, z.B. 21,3306,5432")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="HTTP-Timeout (s)")
    p.add_argument("--port-timeout", type=float, default=DEFAULT_PORT_TIMEOUT, help="Port-Timeout (s)")
    p.add_argument("--user-enum-max", type=int, default=DEFAULT_USER_ENUM_MAX,
                   help="Max. Author-IDs fuer WP User-Enum")
    p.add_argument("--user-agent", default=DEFAULT_UA, help="HTTP User-Agent")
    p.add_argument("--no-color", action="store_true", help="Farben deaktivieren")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Freigabe-Bestaetigung ueberspringen (nur mit Auftrag!)")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.no_color or not sys.stdout.isatty():
        C._enabled = False

    targets: list[str] = list(args.targets)
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                targets += [ln.strip() for ln in fh
                            if ln.strip() and not ln.strip().startswith("#")]
        except OSError as e:
            print(f"Fehler beim Lesen von {args.file}: {e}", file=sys.stderr)
            return 2

    targets = list(dict.fromkeys(targets))   # de-dup, Reihenfolge erhalten
    if not targets:
        build_parser().print_help()
        return 2

    filecfg = load_config_file(args.config)
    wpscan_key = (args.wpscan_api_key or os.environ.get("WPSCAN_API_KEY")
                  or filecfg.get("wpscan_api_key", ""))
    shodan_key = (args.shodan_api_key or os.environ.get("SHODAN_API_KEY")
                  or filecfg.get("shodan_api_key", ""))
    nvd_key = (args.nvd_api_key or os.environ.get("NVD_API_KEY")
               or filecfg.get("nvd_api_key", ""))

    if args.ports:
        try:
            ports = {int(p.strip()): DB_PORTS.get(int(p.strip()), "custom")
                     for p in args.ports.split(",") if p.strip()}
        except ValueError:
            print("Ungueltige --ports Angabe", file=sys.stderr)
            return 2
    else:
        ports = DB_PORTS

    # Freigabe-Hinweis
    if not args.yes:
        print(C.wrap(
            "\n  RECHTLICHER HINWEIS: Nur gegen Systeme einsetzen, fuer die eine\n"
            "  schriftliche Testfreigabe (Scope/Auftrag) vorliegt.\n", C.YELLOW))
        print("  Ziele:")
        for t in targets:
            print(f"    - {t}")
        try:
            ans = input("\n  Testfreigabe vorhanden? Fortfahren? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        if ans not in ("y", "yes", "j", "ja"):
            print("  Abgebrochen.")
            return 1

    cfg = {
        "timeout": args.timeout,
        "port_timeout": args.port_timeout,
        "ua": args.user_agent,
        "user_enum_max": args.user_enum_max,
        "wpscan_api_key": wpscan_key,
        "shodan_api_key": shodan_key,
        "ports": ports,
        "passive_only": args.passive_only,
        "no_ports": args.no_ports,
        "no_http": args.no_http,
        "nvd_client": NvdClient(nvd_key, args.timeout, args.max_cves,
                                enabled=not args.no_cve),
    }

    all_results: list[TargetResult] = []
    for t in targets:
        try:
            res = scan_target(t, cfg)
        except KeyboardInterrupt:
            print("\n  Abgebrochen.")
            break
        except Exception as e:                      # robust weiter
            res = TargetResult(target=t, errors=[f"Interner Fehler: {e}"])
        all_results.append(res)
        print_result(res)

    if args.output:
        payload = []
        for r in all_results:
            d = asdict(r)
            payload.append(d)
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
            print(C.wrap(f"\n  JSON gespeichert: {args.output}", C.GREEN))
        except OSError as e:
            print(f"Fehler beim Schreiben: {e}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
