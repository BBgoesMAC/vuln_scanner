#!/usr/bin/env python3
"""
passive-recon Web-UI — lokaler Webserver (nur Python-Standardlibrary).

Startet ein schoenes lokales Frontend fuer passive_recon.py. Ergebnisse werden
pro Ziel live gestreamt (NDJSON). Bindet standardmaessig nur an 127.0.0.1.

    python3 web_app.py                 # -> http://127.0.0.1:8787
    python3 web_app.py --port 9000
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import webbrowser
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import passive_recon as pr

HERE = os.path.dirname(os.path.abspath(__file__))
FILECFG = pr.load_config_file(None)


def _key(opts: dict, name: str, env: str) -> str:
    """Reihenfolge: Formular -> ENV -> config.json."""
    return (opts.get(name) or os.environ.get(env) or FILECFG.get(name, "") or "").strip()


def build_cfg(opts: dict) -> dict:
    timeout = float(opts.get("timeout") or pr.DEFAULT_TIMEOUT)
    ports_str = (opts.get("ports") or "").strip()
    if ports_str:
        ports = {}
        for p in ports_str.replace(";", ",").split(","):
            p = p.strip()
            if p.isdigit():
                ports[int(p)] = pr.DB_PORTS.get(int(p), "custom")
        if not ports:
            ports = pr.DB_PORTS
    else:
        ports = pr.DB_PORTS

    nvd = pr.NvdClient(
        _key(opts, "nvd_api_key", "NVD_API_KEY"), timeout,
        int(opts.get("max_cves") or pr.DEFAULT_MAX_CVES),
        enabled=not opts.get("no_cve"))

    return {
        "timeout": timeout,
        "port_timeout": float(opts.get("port_timeout") or pr.DEFAULT_PORT_TIMEOUT),
        "ua": pr.DEFAULT_UA,
        "user_enum_max": int(opts.get("user_enum_max") or pr.DEFAULT_USER_ENUM_MAX),
        "wpscan_api_key": _key(opts, "wpscan_api_key", "WPSCAN_API_KEY"),
        "shodan_api_key": _key(opts, "shodan_api_key", "SHODAN_API_KEY"),
        "ports": ports,
        "passive_only": bool(opts.get("passive_only")),
        "no_ports": bool(opts.get("no_ports")),
        "no_http": bool(opts.get("no_http")),
        "nvd_client": nvd,
    }


def parse_targets(raw) -> list[str]:
    if isinstance(raw, list):
        items = raw
    else:
        items = str(raw or "").replace(",", "\n").splitlines()
    out, seen = [], set()
    for t in (x.strip() for x in items):
        if t and not t.startswith("#") and t not in seen:
            seen.add(t)
            out.append(t)
    return out


class Handler(BaseHTTPRequestHandler):
    # HTTP/1.0 => Verbindung wird nach dem Handler geschlossen; der Client
    # erkennt das Stream-Ende am EOF (kein Content-Length noetig).
    protocol_version = "HTTP/1.0"
    server_version = "passive-recon-web"

    def log_message(self, fmt, *args):  # ruhiger Log
        sys.stderr.write("  %s - %s\n" % (self.address_string(), fmt % args))

    # ---- Schutz gegen DNS-Rebinding: nur localhost-Hosts akzeptieren ----
    def _host_ok(self) -> bool:
        host = (self.headers.get("Host", "") or "").split(":")[0]
        return host in ("", "127.0.0.1", "localhost", "::1", "[::1]")

    def do_GET(self):
        if not self._host_ok():
            self.send_error(403, "invalid host")
            return
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._serve_file("index.html", "text/html; charset=utf-8")
        elif path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        else:
            self.send_error(404)

    def _serve_file(self, name: str, ctype: str):
        try:
            with open(os.path.join(HERE, name), "rb") as fh:
                data = fh.read()
        except OSError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if not self._host_ok():
            self.send_error(403, "invalid host")
            return
        if self.path.split("?", 1)[0] != "/api/scan":
            self.send_error(404)
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            opts = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            opts = {}

        # Stream-Header
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        if not opts.get("authorized"):
            self._emit({"type": "error", "index": 0, "target": "",
                        "error": "Bitte Testfreigabe bestaetigen."})
            self._emit({"type": "done"})
            return

        targets = parse_targets(opts.get("targets"))
        if not targets:
            self._emit({"type": "error", "index": 0, "target": "",
                        "error": "Keine gueltigen Ziele angegeben."})
            self._emit({"type": "done"})
            return

        try:
            cfg = build_cfg(opts)
        except Exception as e:
            self._emit({"type": "error", "index": 0, "target": "",
                        "error": f"Konfigurationsfehler: {e}"})
            self._emit({"type": "done"})
            return

        self._emit({"type": "meta", "total": len(targets)})
        for i, t in enumerate(targets):
            self._emit({"type": "start", "index": i, "target": t})
            try:
                res = pr.scan_target(t, cfg)
                self._emit({"type": "result", "index": i, "data": asdict(res)})
            except Exception as e:
                self._emit({"type": "error", "index": i, "target": t,
                            "error": str(e)})
        self._emit({"type": "done"})

    def _emit(self, obj: dict):
        try:
            self.wfile.write((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="passive-recon Web-UI (lokal)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="Bind-Adresse (Default 127.0.0.1 = nur lokal)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--open", action="store_true",
                    help="Browser automatisch oeffnen")
    args = ap.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("  WARNUNG: Bindung an nicht-lokale Adresse — die Web-UI ist dann\n"
              "  im Netzwerk erreichbar. Nur in vertrauenswuerdigen Netzen tun.\n",
              file=sys.stderr)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"\n  passive-recon Web-UI laeuft:  {url}\n  (Strg+C zum Beenden)\n")
    if args.open:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Beendet.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
