#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════╗
# ║  🛡️  HACKATHON AI TEAM — One-Command Startup            ║
# ╚══════════════════════════════════════════════════════════╝

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "🛡️  Agent Ops Center — War Room"
echo "================================"
echo ""

# ── Check for .env ──
if [ ! -f ".env" ]; then
    echo "⚠️  No .env file found."
    echo "   Copying .env.example → .env"
    echo "   Fill in at least one LLM API key before running."
    cp .env.example .env
    echo ""
fi

# ── Install dependencies ──
echo "📦 Installing dependencies..."
if command -v uv &> /dev/null; then
    echo "   Using uv (fast mode)"
    uv pip install -r requirements.txt
else
    pip install -r requirements.txt
fi
echo ""

# ── Create memory directory ──
mkdir -p memory

# ── Launch War Room ──
echo "Launching War Room..."
echo "   URL: http://localhost:8080"
echo ""

uvicorn output.middleware:app --host 0.0.0.0 --port 8080 --reload
