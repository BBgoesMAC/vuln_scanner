#!/usr/bin/env python3
"""
passive-recon — Non-invasive vulnerability reconnaissance for IPs & domains.

Goal: read-only / low-impact checks. NO brute-force, NO fuzzing, NO exploits,
NO write access. Only simple GET requests and single TCP connects (banner grab),
plus an anonymous-FTP login probe with public credentials. Optionally fully
passive via Shodan (no contact with the target at all).

Python standard library only (no external dependencies).

IMPORTANT: Only use against systems for which you have explicit written
authorization to test (scope / engagement).
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import ipaddress
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
from typing import Optional

# --------------------------------------------------------------------------- #
# Configuration / defaults
# --------------------------------------------------------------------------- #

DEFAULT_UA = "passive-recon/1.0 (+authorized security assessment)"
DEFAULT_TIMEOUT = 8.0
DEFAULT_USER_ENUM_MAX = 3          # /?author=1..N  (keep small = non-invasive)
DEFAULT_PORT_TIMEOUT = 3.0
DEFAULT_MAX_HOSTS = 1024           # per-range expansion cap (CIDR / ranges)
DEFAULT_DIRBUST_WORKERS = 16       # concurrency for active directory brute-force
WORDLIST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists")
DEFAULT_WORDLIST_COMMON = os.path.join(WORDLIST_DIR, "common.txt")
DEFAULT_WORDLIST = os.path.join(WORDLIST_DIR, "raft-medium-directories.txt")
WPSCAN_API = "https://wpscan.com/api/v3"
SHODAN_API = "https://api.shodan.io"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_MAX_CVES = 10              # max CVEs per detected product/banner

# SQL/DB and FTP ports to probe (single TCP connect, no login except FTP-anon)
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

# Small, targeted list of common directories for the directory-listing check.
# Deliberately kept small (non-invasive, no fuzzing).
DIR_CANDIDATES = [
    "/", "/wp-content/uploads/", "/wp-content/", "/wp-includes/",
    "/uploads/", "/backup/", "/backups/", "/files/", "/images/",
    "/img/", "/assets/", "/tmp/", "/old/", "/test/", "/.git/",
]

# robots.txt Disallow entries considered "boring/standard" and NOT reported.
# Everything else is flagged as interesting.
ROBOTS_BORING = [
    "/wp-admin/", "/wp-includes/", "/cgi-bin/", "/wp-login.php",
    "/xmlrpc.php", "/", "/*?", "/*?*", "/search/", "/?s=",
    "/feed/", "/comments/", "/trackback/", "/author/",
]

# Keywords that make a robots.txt path particularly interesting.
ROBOTS_JUICY = [
    "admin", "backup", "bak", "old", "config", "conf", "db", "sql",
    "dump", "secret", "private", "priv", "internal", "intern", "test",
    "dev", "staging", "stage", "api", "token", "key", "cred", "password",
    "passwd", "log", "logs", "phpmyadmin", "pma", "adminer", "install",
    "setup", "upload", "tmp", "temp", ".git", ".env", ".svn", "vault",
    "cms", "portal", "restricted", "hidden", "beta", "old_site",
]

# --------------------------------------------------------------------------- #
# Colors
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
# Findings data model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    category: str            # e.g. "wordpress", "directory-listing", "ports"
    title: str
    severity: str = "info"   # info|low|medium|high|critical
    detail: str = ""
    evidence: str = ""       # URL / path / banner

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
# Target expansion (CIDR / IP ranges)
# --------------------------------------------------------------------------- #

def expand_range(token: str) -> Optional[list[str]]:
    """Expand a CIDR or hyphenated IP range into a list of IPs.

    Returns None if the token is not a range/CIDR (caller keeps it as-is).
    Supports:  10.0.0.0/24  ·  10.0.0.1-10.0.0.50  ·  10.0.0.1-50
    """
    token = token.strip()
    if not token:
        return None

    # CIDR (ignore URLs like https://.../path)
    if "/" in token and "://" not in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            return None
        hosts = [str(h) for h in net.hosts()]
        return hosts or [str(net.network_address)]

    # a.b.c.d-a.b.c.d  or  a.b.c.d-N
    m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$',
                 token)
    if m:
        try:
            start = ipaddress.ip_address(m.group(1))
            end_s = m.group(2)
            if "." in end_s:
                end = ipaddress.ip_address(end_s)
            else:
                base = m.group(1).rsplit(".", 1)[0]
                end = ipaddress.ip_address(f"{base}.{end_s}")
        except ValueError:
            return None
        if int(end) < int(start):
            return None
        return [str(ipaddress.ip_address(i))
                for i in range(int(start), int(end) + 1)]

    return None


def expand_targets(tokens: list[str],
                   max_hosts: int = DEFAULT_MAX_HOSTS) -> tuple[list[str], list[str]]:
    """Expand CIDR/ranges to individual hosts. Returns (targets, notes)."""
    out: list[str] = []
    seen: set[str] = set()
    notes: list[str] = []
    for tok in tokens:
        expanded = expand_range(tok)
        if expanded is None:
            items = [tok]
        else:
            if len(expanded) > max_hosts:
                notes.append(f"{tok}: {len(expanded)} hosts capped to {max_hosts} "
                             f"(raise --max-hosts to scan more)")
                expanded = expanded[:max_hosts]
            items = expanded
        for t in items:
            t = t.strip()
            if t and not t.startswith("#") and t not in seen:
                seen.add(t)
                out.append(t)
    return out, notes


# --------------------------------------------------------------------------- #
# HTTP helper (GET only, manual/limited redirect handling)
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
    """A single, harmless GET. Returns None on network error."""
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
    """Find a reachable base URL (https preferred)."""
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
# WordPress detection & version
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
    """Returns (is_wp, version, plugins, themes)."""
    body = base.body
    is_wp = bool(_WP_HINT_RE.search(body)) or bool(_META_GEN_RE.search(body))
    version = None

    m = _META_GEN_RE.search(body)
    if m and m.group(1):
        version = m.group(1)

    plugins = set(_PLUGIN_RE.findall(body))
    themes = set(_THEME_RE.findall(body))

    # readme.html (non-invasive, public file) for the version
    if is_wp and not version:
        r = http_get(base_url.rstrip("/") + "/readme.html", timeout, ua)
        if r and r.status == 200 and "wordpress" in r.body.lower():
            mm = _README_VER_RE.search(r.body)
            if mm:
                version = mm.group(1)

    # RSS feed generator as fallback
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

    # 1) REST API: /wp-json/wp/v2/users  (often open)
    r = http_get(root + "/wp-json/wp/v2/users", timeout, ua)
    if r and r.status == 200 and r.body.strip().startswith("["):
        try:
            users = json.loads(r.body)
            names = [u.get("slug") or u.get("name") for u in users if isinstance(u, dict)]
            names = [n for n in names if n]
            if names:
                findings.append(Finding(
                    "wordpress", "WP user enumeration via REST API possible",
                    "high",
                    detail="Users: " + ", ".join(names[:20]),
                    evidence=root + "/wp-json/wp/v2/users"))
        except json.JSONDecodeError:
            pass

    # 2) /?author=N  -> redirect to /author/<login>/
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
            "wordpress", "WP user enumeration via ?author= possible", "medium",
            detail="ID:login -> " + listing,
            evidence=f"{root}/?author=1"))
    return findings


def check_xmlrpc(base_url: str, timeout: float, ua: str) -> list[Finding]:
    root = base_url.rstrip("/")
    r = http_get(root + "/xmlrpc.php", timeout, ua)
    if r and r.status in (200, 405) and (
            "XML-RPC server accepts POST requests only" in r.body
            or "xmlrpc" in r.body.lower() and r.status == 405):
        return [Finding(
            "wordpress", "XML-RPC enabled (xmlrpc.php reachable)", "medium",
            detail="Can be abused for brute-force / pingback DDoS / amplification. "
                   "Recommendation: disable or restrict.",
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
        return {"__error__": "WPScan API rate limit reached (429)"}
    if r.status == 401:
        return {"__error__": "WPScan API key invalid (401)"}
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
                "wordpress", "WPScan lookup skipped (no API key)",
                "info",
                detail="Set WPSCAN_API_KEY or --wpscan-api-key to enable "
                       "version/plugin CVE lookup."))
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
                title = v.get("title", "Unknown vulnerability")
                refs = v.get("references", {}) or {}
                cve = ""
                if refs.get("cve"):
                    cve = "CVE-" + ", CVE-".join(refs["cve"])
                findings.append(Finding(
                    "wordpress", f"{label}: {title}", "high",
                    detail=cve, evidence=refs.get("url", [""])[0] if refs.get("url") else ""))

    if version:
        _emit(wpscan_lookup("wordpresses", version, api_key, timeout),
              f"WP core {version}")
    for slug in sorted(plugins)[:15]:   # limit (preserve API quota)
        _emit(wpscan_lookup("plugins", slug, api_key, timeout),
              f"Plugin {slug}")
    return findings


# --------------------------------------------------------------------------- #
# Directory listing
# --------------------------------------------------------------------------- #

# Signatures of common directory-listing engines:
#   Apache autoindex / nginx autoindex : "Index of /"
#   Python http.server                  : "Directory listing for"
#   IIS                                 : "[To Parent Directory]"
#   node serve-index (e.g. OWASP Juice  : "listing directory /..." + <ul id="files">
#   Shop /ftp)
_INDEX_OF_RE = re.compile(
    r'<title>\s*Index of /|<h1>\s*Index of /|Directory listing for|'
    r'\[To Parent Directory\]|listing directory\s|'
    r'<ul[^>]*id=["\']files["\']', re.I)


def _normalize_dir_paths(extra_paths: list[str]) -> list[str]:
    """Turn robots.txt Disallow entries into probe paths (strip glob/query,
    keep both with and without a trailing slash)."""
    out: list[str] = []
    for p in extra_paths:
        p = p.split("*")[0].split("?")[0].strip()
        if not p or p == "/":
            continue
        if p not in out:
            out.append(p)
    return out


def check_directory_listing(base_url: str, extra_paths: list[str],
                            timeout: float, ua: str) -> list[Finding]:
    findings: list[Finding] = []
    root = base_url.rstrip("/")
    seen = set()
    # Probe the built-in candidates plus every robots.txt path (with or without
    # a trailing slash). Redirects are followed, so "/ftp" -> "/ftp/" works too.
    paths = list(dict.fromkeys(DIR_CANDIDATES + _normalize_dir_paths(extra_paths)))
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        url = root + path
        r = http_get(url, timeout, ua)
        if r and r.status == 200 and _INDEX_OF_RE.search(r.body):
            findings.append(Finding(
                "directory-listing", f"Directory listing exposed: {path}",
                "medium", evidence=url))
    return findings


def load_wordlist(path: str, limit: int = 0) -> list[str]:
    """Load a directory wordlist (one entry per line; '#' comments ignored)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = [ln.strip().lstrip("/") for ln in fh]
    except OSError:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for w in raw:
        if not w or w.startswith("#") or w in seen:
            continue
        seen.add(w)
        out.append(w)
    return out[:limit] if limit and limit > 0 else out


def check_dirbust(base_url: str, words: list[str], timeout: float, ua: str,
                  workers: int = DEFAULT_DIRBUST_WORKERS,
                  on_hit=None, on_progress=None,
                  progress_every: int = 150) -> list[Finding]:
    """ACTIVE directory brute-force: request /<word> for each word and report
    those that return a directory listing. This is NOT passive — it generates
    one request per word and is noisy in logs. Opt-in only.

    on_hit(finding)          is called (in this thread) as each listing is found.
    on_progress(done, total) is called every `progress_every` completions.
    """
    findings: list[Finding] = []
    root = base_url.rstrip("/")
    total = len(words)

    def _probe(word: str):
        # A single GET; redirects are followed, so "/dir" -> "/dir/" is covered.
        url = f"{root}/{word}"
        r = http_get(url, timeout, ua)
        if r and r.status == 200 and _INDEX_OF_RE.search(r.body):
            return (word, r.final_url or url)
        return None

    done = 0
    with futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(_probe, w): w for w in words}
        for fut in futures.as_completed(futs):
            done += 1
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                word, url = res
                f = Finding(
                    "directory-listing", f"Directory listing exposed: /{word}",
                    "medium", detail="found via wordlist brute-force",
                    evidence=url)
                findings.append(f)
                if on_hit:
                    on_hit(f)
            if on_progress and (done % progress_every == 0 or done == total):
                on_progress(done, total)
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

    # de-dup, prioritize
    interesting = list(dict.fromkeys(interesting))
    for path in interesting:
        low = path.lower()
        sev = "medium" if any(j in low for j in ROBOTS_JUICY) else "low"
        findings.append(Finding(
            "robots", f"Interesting robots.txt entry: {path}", sev,
            evidence=root + path.replace("*", "")))
    return findings, disallowed


# --------------------------------------------------------------------------- #
# Basic-auth prompts (401 + WWW-Authenticate)
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
                    f"HTTP auth prompt ({scheme}) on {path}", "low",
                    detail=f"realm: {realm}" if realm else "",
                    evidence=url))
    return findings


# --------------------------------------------------------------------------- #
# Security headers (bonus, purely passive from the root response)
# --------------------------------------------------------------------------- #

def check_headers(base: HttpResponse, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    h = {k.lower(): v for k, v in base.headers.items()}
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    banner = ", ".join(x for x in [server, powered] if x)
    if banner:
        findings.append(Finding(
            "headers", "Server/technology banner disclosed", "info",
            detail=banner, evidence=base_url))
    missing = []
    for hdr in ("strict-transport-security", "content-security-policy",
                "x-frame-options", "x-content-type-options"):
        if hdr not in h:
            missing.append(hdr)
    if missing:
        findings.append(Finding(
            "headers", "Missing security headers", "low",
            detail=", ".join(missing)))
    return findings


# --------------------------------------------------------------------------- #
# Port checks (TCP connect + banner). Non-invasive: 1 connect, no login,
# except an anonymous-FTP probe with public credentials on port 21.
# --------------------------------------------------------------------------- #

def grab_banner(ip: str, port: int, timeout: float) -> Optional[str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Some services only respond after a prompt/probe. FTP/Redis send a
            # banner unsolicited; MySQL sends its handshake immediately.
            try:
                data = s.recv(256)
            except socket.timeout:
                data = b""
            return data.decode("latin-1", errors="replace").strip() or None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def check_ftp_anonymous(ip: str, timeout: float) -> Optional[Finding]:
    """Probe for anonymous / unauthenticated FTP login using public
    credentials (anonymous / anonymous@). Read-only, low-impact: no writes,
    no brute-force. Reports a HIGH finding if the login succeeds."""
    from ftplib import FTP, all_errors
    ftp = FTP()
    try:
        ftp.connect(ip, 21, timeout=max(timeout, 5.0))
        welcome = (ftp.getwelcome() or "").strip()
        ftp.login("anonymous", "anonymous@example.com")
    except all_errors:
        try:
            ftp.close()
        except Exception:
            pass
        return None

    # Login succeeded -> anonymous access allowed.
    listing: list[str] = []
    try:
        listing = ftp.nlst()[:8]
    except all_errors:
        listing = []
    try:
        ftp.quit()
    except all_errors:
        try:
            ftp.close()
        except Exception:
            pass

    detail = "Anonymous login permitted (user 'anonymous')."
    if welcome:
        detail += f" Banner: {welcome}"
    if listing:
        detail += " | root listing: " + ", ".join(listing)
    return Finding(
        "ports", "Anonymous / unauthenticated FTP login allowed", "high",
        detail=detail, evidence=f"{ip}:21")


def check_ports(ip: str, ports: dict, timeout: float,
                max_workers: int = 8) -> tuple[list[Finding], list[tuple]]:
    """Returns (findings, banners). banners: [(banner, evidence, hint)]."""
    findings: list[Finding] = []
    banners: list[tuple] = []
    open_ports: set[int] = set()

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
            open_ports.add(port)
            sev = "high" if port in (3306, 5432, 1433, 1521, 27017, 6379,
                                     9200, 11211, 5984) else "medium"
            detail = f"Banner: {banner}" if banner else "Port open (no banner)"
            findings.append(Finding(
                "ports", f"Open port {port}/tcp ({name})", sev,
                detail=detail, evidence=f"{ip}:{port}"))
            if banner:
                banners.append((banner, f"{ip}:{port}", name))

    # Anonymous-FTP probe when port 21 is open.
    if 21 in open_ports:
        anon = check_ftp_anonymous(ip, timeout)
        if anon:
            findings.append(anon)

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

# Each entry: (regex with version group, display name, [CPE candidates]).
# CPE candidates are queried in order; the first match wins.
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
    """Extract (display name, [CPE candidates]) from a banner string."""
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

    # DB handshakes (version is in cleartext but without the product name)
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
    """Queries the NVD API (with throttling + cache). No key required, but
    recommended (5 vs. 50 requests / 30 s)."""

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
                    "cve", f"{name}: +{len(scored) - len(top)} more CVEs",
                    "info", detail=f"truncated (raise --max-cves); CPE {used}"))
        return findings


# --------------------------------------------------------------------------- #
# Shodan (fully passive, optional)
# --------------------------------------------------------------------------- #

def shodan_lookup(ip: str, api_key: str, timeout: float) -> list[Finding]:
    findings: list[Finding] = []
    url = f"{SHODAN_API}/shodan/host/{ip}?key={api_key}"
    r = http_get(url, timeout, DEFAULT_UA)
    if not r or r.status != 200:
        if r and r.status == 401:
            findings.append(Finding("shodan", "Shodan API key invalid", "info"))
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
            "shodan", f"[Shodan] port {port}/tcp {name} {product}".strip(),
            sev, evidence=f"{ip}:{port}"))
    for vuln in data.get("vulns", []):
        findings.append(Finding("shodan", f"[Shodan] {vuln}", "high"))
    return findings


# --------------------------------------------------------------------------- #
# Per-target scan orchestration
# --------------------------------------------------------------------------- #

def plan_tasks(cfg: dict) -> list[str]:
    """Return the ordered list of task names a scan will run (for the UI)."""
    if cfg.get("passive_only"):
        return ["shodan"]
    tasks: list[str] = []
    if not cfg.get("no_ports"):
        tasks.append("ports")
    if cfg.get("shodan_api_key"):
        tasks.append("shodan")
    if not cfg.get("no_http"):
        tasks.append("http")
    nvd = cfg.get("nvd_client")
    if nvd and getattr(nvd, "enabled", False) and not (
            cfg.get("no_http") and cfg.get("no_ports")):
        tasks.append("cve")
    if cfg.get("dirbust"):
        for pname, words in cfg.get("dirbust_phases", []):
            if words:
                tasks.append(f"dirbust-{pname}")
    return tasks


def scan_target(target: str, cfg: dict, emit=None) -> TargetResult:
    """Run all configured checks against one target.

    If `emit` is given, it is called (in this thread) with streaming events:
    {"type":"target_meta",...}, {"type":"task",...}, {"type":"finding",...}.
    Findings are also accumulated into the returned TargetResult.
    """
    res = TargetResult(target=target)
    timeout = cfg["timeout"]
    ua = cfg["ua"]

    def _emit(ev: dict):
        if emit:
            try:
                emit(ev)
            except Exception:
                pass

    def add(f: Finding):
        res.add(f)
        _emit({"type": "finding", "data": asdict(f)})

    def task(name: str, status: str, **extra):
        _emit({"type": "task", "task": name, "status": status, **extra})

    res.resolved_ip = resolve_ip(target)
    _emit({"type": "target_meta", "resolved_ip": res.resolved_ip})

    # ---- Fully passive mode: Shodan only ----
    if cfg.get("passive_only"):
        task("shodan", "running")
        n = 0
        if res.resolved_ip and cfg.get("shodan_api_key"):
            for f in shodan_lookup(res.resolved_ip, cfg["shodan_api_key"], timeout):
                add(f); n += 1
        else:
            res.errors.append("passive-only: requires a resolvable IP + Shodan key")
        task("shodan", "done", found=n)
        return res

    banners_for_cve: list[tuple] = []   # (banner, evidence, hint)

    # ---- Port checks ----
    if not cfg.get("no_ports"):
        task("ports", "running")
        n = 0
        if res.resolved_ip:
            port_findings, port_banners = check_ports(
                res.resolved_ip, cfg["ports"], cfg["port_timeout"])
            for f in port_findings:
                add(f); n += 1
            banners_for_cve += port_banners
            task("ports", "done", found=n)
        else:
            task("ports", "skipped")

    # ---- Optionally Shodan ----
    if cfg.get("shodan_api_key"):
        task("shodan", "running")
        n = 0
        if res.resolved_ip:
            for f in shodan_lookup(res.resolved_ip, cfg["shodan_api_key"], timeout):
                add(f); n += 1
            task("shodan", "done", found=n)
        else:
            task("shodan", "skipped")

    # ---- Reach a base URL (needed for HTTP checks and/or dirbust) ----
    need_http = not cfg.get("no_http")
    need_dirbust = bool(cfg.get("dirbust") and cfg.get("dirbust_phases"))
    base = None
    if need_http or need_dirbust:
        base = pick_base_url(target, timeout, ua)
        if base is not None:
            res.base_url = base.final_url
            _emit({"type": "target_meta", "resolved_ip": res.resolved_ip,
                   "base_url": res.base_url})

    dir_seen: set[str] = set()

    # ---- HTTP-based checks ----
    if need_http:
        task("http", "running")
        if base is None:
            res.errors.append("No HTTP(S) reachable")
            task("http", "skipped")
        else:
            base_url = base.final_url
            n = 0
            for f in check_headers(base, base_url):
                add(f); n += 1

            _h = {k.lower(): v for k, v in base.headers.items()}
            for hk in ("server", "x-powered-by"):
                if _h.get(hk):
                    banners_for_cve.append((_h[hk], base_url, "http"))

            robots_findings, disallowed = check_robots(base_url, timeout, ua)
            for f in robots_findings:
                add(f); n += 1

            for f in check_basic_auth(base_url, timeout, ua):
                add(f); n += 1

            for f in check_directory_listing(base_url, disallowed, timeout, ua):
                if f.title not in dir_seen:
                    dir_seen.add(f.title); add(f); n += 1

            is_wp, version, plugins, themes = detect_wordpress(
                base, base_url, timeout, ua)
            if is_wp:
                v = f" (version {version})" if version else " (version unknown)"
                add(Finding("wordpress", f"WordPress detected{v}", "info",
                            detail=(f"Plugins: {', '.join(sorted(plugins))}"
                                    if plugins else ""),
                            evidence=base_url)); n += 1
                for f in check_xmlrpc(base_url, timeout, ua):
                    add(f); n += 1
                for f in check_user_enum(base_url, timeout, ua, cfg["user_enum_max"]):
                    add(f); n += 1
                for f in wpscan_findings(is_wp, version, plugins,
                                         cfg.get("wpscan_api_key", ""), timeout):
                    add(f); n += 1
            task("http", "done", found=n)

    # ---- Banner -> CVE (NVD) ----
    nvd: Optional[NvdClient] = cfg.get("nvd_client")
    if nvd and nvd.enabled and not (cfg.get("no_http") and cfg.get("no_ports")):
        task("cve", "running")
        n = 0
        if banners_for_cve:
            seen_cve: set[str] = set()
            for banner, evidence, hint in banners_for_cve:
                for f in nvd.cve_findings(banner, evidence, hint):
                    key = f.evidence or f.title
                    if key in seen_cve:
                        continue
                    seen_cve.add(key); add(f); n += 1
        task("cve", "done", found=n)

    # ---- ACTIVE (opt-in): phased directory brute-force (common, then large) ----
    if need_dirbust and res.base_url:
        base_url = res.base_url
        workers = cfg.get("dirbust_workers", DEFAULT_DIRBUST_WORKERS)
        for pname, words in cfg["dirbust_phases"]:
            if not words:
                continue
            tname = f"dirbust-{pname}"
            task(tname, "running", done=0, total=len(words))
            counter = {"n": 0}

            def _on_hit(f, counter=counter):
                if f.title in dir_seen:
                    return
                dir_seen.add(f.title)
                counter["n"] += 1
                add(f)

            def _on_prog(done, total, tname=tname, counter=counter):
                task(tname, "running", done=done, total=total, found=counter["n"])

            check_dirbust(base_url, words, timeout, ua, workers,
                          on_hit=_on_hit, on_progress=_on_prog)
            task(tname, "done", found=counter["n"])

    return res


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def print_result(res: TargetResult) -> None:
    print()
    print(C.wrap("=" * 70, C.BLUE))
    ip = f"  ({res.resolved_ip})" if res.resolved_ip else ""
    print(C.wrap(f" TARGET: {res.target}{ip}", C.BOLD))
    if res.base_url:
        print(C.wrap(f" URL:    {res.base_url}", C.DIM))
    print(C.wrap("=" * 70, C.BLUE))

    if res.errors:
        for e in res.errors:
            print(C.wrap(f"  [!] {e}", C.YELLOW))

    if not res.findings:
        print(C.wrap("  No findings.", C.DIM))
        return

    findings = sorted(res.findings, key=lambda f: (SEV_ORDER.get(f.severity, 9),
                                                   f.category))
    for f in findings:
        print(f.line())

    # Summary
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
# Load config
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
        description="Non-invasive vulnerability reconnaissance (read-only).",
        epilog="Only use with explicit written authorization.")
    p.add_argument("targets", nargs="*",
                   help="IPs, domains, CIDRs (10.0.0.0/24) or ranges (10.0.0.1-50)")
    p.add_argument("-f", "--file", help="File with targets (one per line)")
    p.add_argument("-o", "--output", help="Write results to a JSON file")
    p.add_argument("--config", help="Path to config.json")
    p.add_argument("--wpscan-api-key", help="WPScan API key (or WPSCAN_API_KEY / config.json)")
    p.add_argument("--shodan-api-key", help="Shodan API key (or SHODAN_API_KEY / config.json)")
    p.add_argument("--nvd-api-key", help="NVD API key for banner CVE lookup "
                   "(or NVD_API_KEY / config.json; optional, but faster)")
    p.add_argument("--no-cve", action="store_true",
                   help="Disable banner CVE lookup (NVD)")
    p.add_argument("--max-cves", type=int, default=DEFAULT_MAX_CVES,
                   help="Max CVEs per detected product/banner")
    p.add_argument("--max-hosts", type=int, default=DEFAULT_MAX_HOSTS,
                   help="Max hosts to expand per CIDR/range")
    p.add_argument("--passive-only", action="store_true",
                   help="Fully passive: no contact with the target, Shodan only")
    p.add_argument("--no-ports", action="store_true", help="Skip port checks")
    p.add_argument("--no-http", action="store_true", help="Skip HTTP checks")
    p.add_argument("--dirbust", action="store_true",
                   help="ACTIVE directory brute-force in phases (noisy, not passive): "
                        "a fast 'common' list first, then the large one")
    p.add_argument("--wordlist-common", default=DEFAULT_WORDLIST_COMMON,
                   help="Fast first-phase wordlist (default: bundled common.txt)")
    p.add_argument("--wordlist", default=DEFAULT_WORDLIST,
                   help="Large second-phase wordlist (default: bundled raft-medium-directories.txt)")
    p.add_argument("--dirbust-limit", type=int, default=0,
                   help="Cap the number of entries per phase (0 = all)")
    p.add_argument("--dirbust-workers", type=int, default=DEFAULT_DIRBUST_WORKERS,
                   help="Concurrent requests for --dirbust")
    p.add_argument("--ports", help="Override port list, comma-separated, e.g. 21,3306,5432")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="HTTP timeout (s)")
    p.add_argument("--port-timeout", type=float, default=DEFAULT_PORT_TIMEOUT, help="Port timeout (s)")
    p.add_argument("--user-enum-max", type=int, default=DEFAULT_USER_ENUM_MAX,
                   help="Max author IDs for WP user enumeration")
    p.add_argument("--user-agent", default=DEFAULT_UA, help="HTTP User-Agent")
    p.add_argument("--no-color", action="store_true", help="Disable colors")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip the authorization confirmation (only with an engagement!)")
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
            print(f"Error reading {args.file}: {e}", file=sys.stderr)
            return 2

    targets, notes = expand_targets(targets, args.max_hosts)
    if not targets:
        build_parser().print_help()
        return 2
    for n in notes:
        print(C.wrap(f"  [i] {n}", C.YELLOW))

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
            print("Invalid --ports value", file=sys.stderr)
            return 2
    else:
        ports = DB_PORTS

    dirbust_phases: list[tuple] = []
    if args.dirbust:
        common = load_wordlist(args.wordlist_common, args.dirbust_limit)
        large = load_wordlist(args.wordlist, args.dirbust_limit)
        cset = set(common)
        large = [w for w in large if w not in cset]   # skip words already in common
        if common:
            dirbust_phases.append(("common", common))
        if large:
            dirbust_phases.append(("large", large))
        if not dirbust_phases:
            print(C.wrap(f"  [!] --dirbust: no wordlist entries loaded "
                         f"({args.wordlist_common} / {args.wordlist})", C.YELLOW))
        else:
            total = sum(len(w) for _, w in dirbust_phases)
            phases = " -> ".join(f"{n}:{len(w)}" for n, w in dirbust_phases)
            print(C.wrap(f"  [i] ACTIVE directory brute-force: {phases} "
                         f"= {total} requests per target (noisy!)", C.YELLOW))

    # Authorization notice
    if not args.yes:
        print(C.wrap(
            "\n  LEGAL NOTICE: Only use against systems for which you have\n"
            "  explicit written authorization to test (scope / engagement).\n",
            C.YELLOW))
        print("  Targets:")
        for t in targets[:50]:
            print(f"    - {t}")
        if len(targets) > 50:
            print(f"    ... and {len(targets) - 50} more")
        try:
            ans = input("\n  Authorized to test these targets? Continue? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        if ans not in ("y", "yes"):
            print("  Aborted.")
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
        "dirbust": args.dirbust,
        "dirbust_phases": dirbust_phases,
        "dirbust_workers": args.dirbust_workers,
        "nvd_client": NvdClient(nvd_key, args.timeout, args.max_cves,
                                enabled=not args.no_cve),
    }

    all_results: list[TargetResult] = []
    for t in targets:
        try:
            res = scan_target(t, cfg)
        except KeyboardInterrupt:
            print("\n  Aborted.")
            break
        except Exception as e:                      # keep going, stay robust
            res = TargetResult(target=t, errors=[f"Internal error: {e}"])
        all_results.append(res)
        print_result(res)

    if args.output:
        payload = []
        for r in all_results:
            payload.append(asdict(r))
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
            print(C.wrap(f"\n  JSON saved: {args.output}", C.GREEN))
        except OSError as e:
            print(f"Error writing file: {e}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
