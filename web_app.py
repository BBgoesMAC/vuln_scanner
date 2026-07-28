#!/usr/bin/env python3
"""
passive-recon web UI — local web server (Python standard library only).

Serves a nice local frontend for passive_recon.py. Results are streamed live
per target (NDJSON). Binds to 127.0.0.1 only by default.

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
    """Priority: form -> ENV -> config.json."""
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

    dirbust = bool(opts.get("dirbust"))
    dirbust_words = []
    if dirbust:
        wl = (opts.get("wordlist") or "").strip() or pr.DEFAULT_WORDLIST
        try:
            limit = int(opts.get("dirbust_limit") or 0)
        except (TypeError, ValueError):
            limit = 0
        dirbust_words = pr.load_wordlist(wl, limit)

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
        "dirbust": dirbust,
        "dirbust_words": dirbust_words,
        "dirbust_workers": int(opts.get("dirbust_workers") or pr.DEFAULT_DIRBUST_WORKERS),
        "nvd_client": nvd,
    }


def parse_targets(raw) -> list[str]:
    """Split raw input into tokens, then expand CIDRs/ranges."""
    if isinstance(raw, list):
        items = raw
    else:
        items = str(raw or "").replace(",", "\n").splitlines()
    return [x.strip() for x in items if x.strip()]


class Handler(BaseHTTPRequestHandler):
    # HTTP/1.0 => the connection is closed after the handler; the client
    # detects the end of the stream at EOF (no Content-Length needed).
    protocol_version = "HTTP/1.0"
    server_version = "passive-recon-web"

    def log_message(self, fmt, *args):  # quieter log
        sys.stderr.write("  %s - %s\n" % (self.address_string(), fmt % args))

    # ---- DNS-rebinding protection: accept localhost hosts only ----
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

        # Streaming headers
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        if not opts.get("authorized"):
            self._emit({"type": "error", "index": 0, "target": "",
                        "error": "Please confirm authorization."})
            self._emit({"type": "done"})
            return

        tokens = parse_targets(opts.get("targets"))
        try:
            max_hosts = int(opts.get("max_hosts") or pr.DEFAULT_MAX_HOSTS)
        except (TypeError, ValueError):
            max_hosts = pr.DEFAULT_MAX_HOSTS
        targets, notes = pr.expand_targets(tokens, max_hosts)

        if not targets:
            self._emit({"type": "error", "index": 0, "target": "",
                        "error": "No valid targets provided."})
            self._emit({"type": "done"})
            return

        try:
            cfg = build_cfg(opts)
        except Exception as e:
            self._emit({"type": "error", "index": 0, "target": "",
                        "error": f"Configuration error: {e}"})
            self._emit({"type": "done"})
            return

        for n in notes:
            self._emit({"type": "note", "text": n})
        if opts.get("dirbust"):
            n_words = len(cfg.get("dirbust_words") or [])
            if n_words:
                self._emit({"type": "note", "text": f"ACTIVE directory "
                            f"brute-force: {n_words} entries per target (noisy!)"})
            else:
                self._emit({"type": "note", "text": "dirbust enabled but wordlist "
                            "is empty / not found"})
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
    ap = argparse.ArgumentParser(description="passive-recon web UI (local)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="Bind address (default 127.0.0.1 = local only)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--open", action="store_true",
                    help="Open the browser automatically")
    args = ap.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("  WARNING: binding to a non-local address — the web UI will then\n"
              "  be reachable on the network. Only do this on trusted networks.\n",
              file=sys.stderr)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"\n  passive-recon web UI running:  {url}\n  (Ctrl+C to stop)\n")
    if args.open:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
