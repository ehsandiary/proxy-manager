#!/usr/bin/env bash
# Builds dist/proxymgr-install.sh (installer + embedded app) and dist/install-node.sh
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p dist
{
  cat install-main.sh
  echo "__PAYLOAD__"
  tar czf - --exclude='__pycache__' --exclude='*.pyc' app tools requirements.txt VERSION | base64 -w 76
} > dist/proxymgr-install.sh
chmod +x dist/proxymgr-install.sh
cp app/static/install-node.sh dist/install-node.sh
chmod +x dist/install-node.sh
