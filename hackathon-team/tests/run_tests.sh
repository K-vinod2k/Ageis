#!/bin/bash
# Run full Aegis test suite against a running server
# Usage:
#   ./tests/run_tests.sh                          # local
#   AEGIS_TEST_URL=https://8080-xxx.cloudspaces.litng.ai ./tests/run_tests.sh

set -e

URL=${AEGIS_TEST_URL:-"http://localhost:8080"}
echo "============================================"
echo " AEGIS SECURITY TEST SUITE"
echo " Target: $URL"
echo "============================================"

# Check server is up
echo "Checking server health..."
if ! curl -sf "$URL/health" > /dev/null; then
    echo "ERROR: Server not reachable at $URL"
    echo "Start it with: uv run python -m uvicorn output.middleware:app --host 0.0.0.0 --port 8080"
    exit 1
fi
echo "Server is UP"
echo ""

# Run tests
AEGIS_TEST_URL="$URL" uv run pytest tests/ \
    -v \
    --tb=short \
    --no-header \
    -q \
    2>&1

echo ""
echo "Evidence logs written to: tests/evidence/"
ls -la tests/evidence/ 2>/dev/null || echo "(no evidence dir yet)"
