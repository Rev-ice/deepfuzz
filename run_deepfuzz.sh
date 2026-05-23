#!/bin/bash
#
# DeepFuzz -- One-shot build & run script
#
# Usage:
#   ./run_deepfuzz.sh xz ./targets/xz/xz ./seeds/xz /tmp/deepfuzz_xz
#
# Steps:
#   1. Install Python dependencies
#   2. Build depth model (angr)
#   3. Init config pool
#   4. Start Python daemon
#   5. Launch AFL++ (modified with DeepFuzz)
#

set -e

TARGET_NAME="${1:-xz}"
TARGET_BIN="${2:-./target}"
SEED_DIR="${3:-./seeds}"
OUT_DIR="${4:-/tmp/deepfuzz_out}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEEPFUZZ_PY="${SCRIPT_DIR}/deepfuzz_py"

echo "=== DeepFuzz ==="
echo "Target:       ${TARGET_NAME}"
echo "Binary:       ${TARGET_BIN}"
echo "Seeds:        ${SEED_DIR}"
echo "Output:       ${OUT_DIR}"
echo ""

# Step 0: Check dependencies
echo "[*] Checking dependencies..."

if [ ! -f "${TARGET_BIN}" ]; then
    echo "[!] Target binary not found: ${TARGET_BIN}"
    exit 1
fi

if [ ! -d "${SEED_DIR}" ]; then
    echo "[!] Seed directory not found: ${SEED_DIR}"
    exit 1
fi

# Create output directory
mkdir -p "${OUT_DIR}"

# Step 1: Install Python dependencies
echo "[*] Installing Python dependencies..."
pip3 install -q -r "${DEEPFUZZ_PY}/requirements.txt" 2>/dev/null || {
    echo "[!] pip install failed, continuing anyway..."
}

# Step 2: Build depth model
DEPTH_MODEL="${OUT_DIR}/depth_model.json"
echo "[*] Building depth model..."
python3 "${DEEPFUZZ_PY}/deepfuzz_build_depth_model.py" \
    --binary "${TARGET_BIN}" \
    --output "${DEPTH_MODEL}" \
    --no-libs 2>/dev/null || {
    echo "[!] Depth model build failed, creating placeholder..."
    cat > "${DEPTH_MODEL}" << 'EOFPLACEHOLDER'
{
  "map_size": 65536,
  "max_depth": 1.0,
  "binary": "placeholder",
  "num_functions": 0,
  "num_edges": 0,
  "edges": {}
}
EOFPLACEHOLDER
}

# Step 2b: Warmup — dynamic depth calibration
echo "[*] Running warmup phase..."
python3 "${DEEPFUZZ_PY}/deepfuzz_warmup.py" \
    --binary "${TARGET_BIN}" \
    --seeds "${SEED_DIR}" \
    --depth-model "${DEPTH_MODEL}" \
    --output "${OUT_DIR}" 2>/dev/null && {
    # use calibrated model if warmup succeeded
    if [ -f "${OUT_DIR}/depth_model_calibrated.json" ]; then
        DEPTH_MODEL="${OUT_DIR}/depth_model_calibrated.json"
        echo "[*] Using calibrated depth model"
    fi
} || echo "[*] Warmup skipped (target may not be instrumented with -finstrument-functions)"

# Step 3: Init config pool
echo "[*] Initializing config pool..."
python3 "${DEEPFUZZ_PY}/deepfuzz_main.py" \
    --target "${TARGET_NAME}" \
    --afl-output "${OUT_DIR}" \
    --mode init

# Step 4: Start Python daemon (background)
echo "[*] Starting Python daemon..."
python3 "${DEEPFUZZ_PY}/deepfuzz_main.py" \
    --target "${TARGET_NAME}" \
    --afl-output "${OUT_DIR}" \
    --depth-model "${DEPTH_MODEL}" \
    --mode daemon &
DAEMON_PID=$!
echo "    Daemon PID: ${DAEMON_PID}"

# Step 5: Launch AFL++
echo "[*] Launching AFL++ (DeepFuzz)..."
echo ""

# Build afl-fuzz first
cd "${SCRIPT_DIR}"
make clean > /dev/null 2>&1 || true
make -j"$(nproc 2>/dev/null || echo 4)" afl-fuzz

# Run
exec ./afl-fuzz \
    -i "${SEED_DIR}" \
    -o "${OUT_DIR}" \
    -J "${DEPTH_MODEL}" \
    -- "${TARGET_BIN}" @@

# Cleanup on exit
kill ${DAEMON_PID} 2>/dev/null || true
