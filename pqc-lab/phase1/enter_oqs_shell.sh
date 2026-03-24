#!/usr/bin/env bash
set -euo pipefail

PHASE1_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$PHASE1_DIR/workspace"
IMAGE="openquantumsafe/curl:latest"

mkdir -p "$WORKSPACE_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "❌ Docker CLI not found. Install Docker Desktop first."
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "❌ Docker daemon is not running. Start Docker Desktop and retry."
  exit 1
fi

echo "Launching OQS shell..."
echo "Local workspace: $WORKSPACE_DIR"
echo "Container path : /opt/test"

docker run -it --rm \
  -v "$WORKSPACE_DIR:/opt/test" \
  -w /opt/test \
  "$IMAGE" sh
