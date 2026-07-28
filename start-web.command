#!/bin/bash
# Double-click launcher for the passive-recon web UI (macOS).
cd "$(dirname "$0")" || exit 1
exec python3 web_app.py --open
