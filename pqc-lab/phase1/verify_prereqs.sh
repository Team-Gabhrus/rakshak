#!/usr/bin/env bash
set -euo pipefail

PHASE1_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$PHASE1_DIR/workspace"
IMAGE="openquantumsafe/curl:latest"

echo "[1/4] Checking Docker CLI..."
if ! command -v docker >/dev/null 2>&1; then
  echo "❌ Docker CLI not found. Install Docker Desktop first."
  exit 1
fi

echo "[2/4] Checking Docker daemon..."
if ! docker info >/dev/null 2>&1; then
  echo "❌ Docker daemon is not running. Start Docker Desktop and retry."
  exit 1
fi

echo "[3/4] Ensuring workspace exists: $WORKSPACE_DIR"
mkdir -p "$WORKSPACE_DIR"

echo "[4/4] Pulling/verifying image: $IMAGE"
docker pull "$IMAGE" >/dev/null

echo "✅ Phase 1 prerequisites are ready."
echo "Next: ./pqc-lab/phase1/enter_oqs_shell.sh"
