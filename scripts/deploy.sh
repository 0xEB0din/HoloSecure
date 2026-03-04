#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# HoloSecure — deployment helper
#
# Usage:
#   ./scripts/deploy.sh              # deploy to dev (default)
#   ./scripts/deploy.sh prod         # deploy to prod
#   ./scripts/deploy.sh dev --guided # first-time setup
# ──────────────────────────────────────────────────────────────

set -euo pipefail

ENV="${1:-dev}"
EXTRA_ARGS="${*:2}"

echo "╔══════════════════════════════════════╗"
echo "║        HoloSecure Deployment         ║"
echo "║        Environment: ${ENV}              ║"
echo "╚══════════════════════════════════════╝"

# Validate
echo "[1/4] Validating template..."
sam validate --lint

# Run tests
echo "[2/4] Running test suite..."
python -m pytest tests/ -v --tb=short || {
    echo "ERROR: Tests failed. Fix before deploying."
    exit 1
}

# Build
echo "[3/4] Building Lambda packages..."
sam build

# Deploy
echo "[4/4] Deploying to ${ENV}..."
if [ "$ENV" = "prod" ]; then
    sam deploy --config-env prod $EXTRA_ARGS
else
    sam deploy $EXTRA_ARGS
fi

echo ""
echo "Deployment complete."
echo "Dashboard: check CloudWatch console for HoloSecure-${ENV} dashboard."
