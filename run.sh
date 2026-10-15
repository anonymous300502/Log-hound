#!/usr/bin/env bash
# ==============================================================================
# LogHound — Single-command build, ingest, and startup script
# Works out-of-the-box on any Linux or macOS machine with Rust, Node, and Python.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$SCRIPT_DIR"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8080}"
DB_PATH="${DB_PATH:-loghound.duckdb}"
SAMPLE_SIZE="${SAMPLE_SIZE:-50000}"
REBUILD=0

# Parse optional arguments
for arg in "$@"; do
  case "$arg" in
    --rebuild)
      REBUILD=1
      shift
      ;;
    --help|-h)
      echo "Usage: ./run.sh [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --rebuild       Force rebuilding backend and frontend"
      echo "  -h, --help      Show this help message"
      echo ""
      echo "Environment variables:"
      echo "  HOST            Host address to bind (default: 127.0.0.1)"
      echo "  PORT            Port to bind (default: 8080)"
      echo "  DB_PATH         DuckDB database file (default: loghound.duckdb)"
      echo "  SAMPLE_SIZE     Events to generate if DB missing (default: 50000)"
      exit 0
      ;;
  esac
done

echo "--------------------------------------------------------"
echo "  LogHound: Automated Startup"
echo "--------------------------------------------------------"

# 1. Dependency verification
echo "[1/4] Checking prerequisites..."

if ! command -v cargo >/dev/null 2>&1; then
  echo "Error: Rust/Cargo is not installed or not in PATH."
  echo "Install it via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  exit 1
fi

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "Error: Node.js and npm are required to build the frontend."
  echo "Please install Node.js 18+ (https://nodejs.org)."
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Warning: python3 not found. Ingesting existing database only."
fi

# 2. Backend binary build
echo "[2/4] Verifying backend binary..."
if [ ! -f "target/release/loghound" ] || [ "$REBUILD" -eq 1 ]; then
  echo "Building loghound backend in release mode..."
  # If low memory, allow disabling LTO automatically if needed
  CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 cargo build --release
else
  echo "Backend binary already built: target/release/loghound"
fi

# 3. Frontend production build
echo "[3/4] Verifying frontend assets..."
if [ ! -d "frontend/dist" ] || [ ! -f "frontend/dist/index.html" ] || [ "$REBUILD" -eq 1 ]; then
  echo "Building frontend production assets..."
  (
    cd frontend
    if [ ! -d "node_modules" ]; then
      npm install --no-audit --no-fund
    fi
    npm run build
  )
else
  echo "Frontend assets ready in frontend/dist"
fi

# 4. Ingest sample data if database does not exist
echo "[4/4] Verifying investigation corpus..."
if [ ! -f "$DB_PATH" ]; then
  SAMPLE_LOG="sample_logs_${SAMPLE_SIZE}.log"
  if [ ! -f "$SAMPLE_LOG" ]; then
    echo "Generating ${SAMPLE_SIZE} synthetic security events..."
    python3 scripts/gen_sample_logs.py "$SAMPLE_SIZE" "$SAMPLE_LOG"
  fi
  echo "Ingesting security events into DuckDB ($DB_PATH)..."
  ./target/release/loghound ingest "$SAMPLE_LOG" "$DB_PATH" config/mappings.yaml
else
  echo "Found existing database: $DB_PATH"
fi

# 5. Start serving
ADDR="${HOST}:${PORT}"
echo ""
echo "========================================================"
echo "  LogHound is ready!"
echo "  Access Web UI at:  http://${ADDR}/"
echo "  API Stats at:      http://${ADDR}/api/stats"
echo "========================================================"
echo "Starting server... (Press Ctrl+C to stop)"
echo ""

exec ./target/release/loghound serve "$DB_PATH" "$ADDR"
