#!/bin/bash
# Doppelklick-Starter fuer die passive-recon Web-UI (macOS).
cd "$(dirname "$0")" || exit 1
exec python3 web_app.py --open
