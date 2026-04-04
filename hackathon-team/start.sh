#!/usr/bin/env bash
# AEGIS — One command startup for Lightning AI Studios
# Runs everything: War Room UI + Webhook Shield + Agent API on port 8080

set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  AEGIS — Zero-Trust Threat Analyst       ║"
echo "║  Starting on http://0.0.0.0:8080         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Install deps silently if needed
uv pip install -r requirements.txt -q 2>/dev/null || pip install -r requirements.txt -q

echo "  War Room UI  → open port 8080 in Lightning AI"
echo "  Webhook Demo → POST /webhook/github"
echo "  Clean demo   → GET  /demo/clean-pr"
echo "  Poisoned demo→ GET  /demo/poisoned-pr"
echo ""

uv run python -m uvicorn output.middleware:app \
    --host 0.0.0.0 \
    --port 8080 \
    --reload
