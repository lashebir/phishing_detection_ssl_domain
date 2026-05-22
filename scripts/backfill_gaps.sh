#!/bin/bash
#
# Automated Gap Backfilling for CT Log Collection
#
# This script:
# 1. Detects gaps in collected certificate data using detect_gaps.py
# 2. Generates backfill commands for each gap
# 3. Optionally executes backfill automatically
#
# Usage:
#   ./scripts/backfill_gaps.sh sources/raw/certs_streaming_48h.jsonl
#   ./scripts/backfill_gaps.sh --auto sources/raw/certs_streaming_48h.jsonl
#   ./scripts/backfill_gaps.sh --min-gap-size 100 --max-gaps 5 sources/raw/certs_streaming_48h.jsonl
#

set -e

cd "$(dirname "$0")/.."

# ── Configuration ─────────────────────────────────────────────────────────────

MIN_GAP_SIZE=10        # Minimum gap size to backfill
MAX_GAPS=10            # Maximum number of gaps to backfill in one run
AUTO_EXECUTE=false     # Auto-execute backfills without prompting
DRY_RUN=false         # Print commands without executing

# ── Parse arguments ───────────────────────────────────────────────────────────

INPUT_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --min-gap-size)
            MIN_GAP_SIZE="$2"
            shift 2
            ;;
        --max-gaps)
            MAX_GAPS="$2"
            shift 2
            ;;
        --auto)
            AUTO_EXECUTE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS] <input_file>"
            echo ""
            echo "Options:"
            echo "  --min-gap-size N   Minimum gap size to backfill (default: 10)"
            echo "  --max-gaps N       Maximum gaps to process (default: 10)"
            echo "  --auto             Auto-execute without prompting"
            echo "  --dry-run          Print commands without executing"
            echo "  --help             Show this help"
            echo ""
            exit 0
            ;;
        -*)
            echo "Error: Unknown option $1"
            exit 1
            ;;
        *)
            INPUT_FILE="$1"
            shift
            ;;
    esac
done

# ── Validate input ────────────────────────────────────────────────────────────

if [ -z "${INPUT_FILE}" ]; then
    echo "Error: No input file specified"
    echo "Usage: $0 [OPTIONS] <input_file>"
    exit 1
fi

if [ ! -f "${INPUT_FILE}" ]; then
    echo "Error: File not found: ${INPUT_FILE}"
    exit 1
fi

# ── Header ────────────────────────────────────────────────────────────────────

echo "════════════════════════════════════════════════════════════════════════════"
echo "  CT Log Gap Backfilling"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "  Input file:         ${INPUT_FILE}"
echo "  Min gap size:       ${MIN_GAP_SIZE}"
echo "  Max gaps to fill:   ${MAX_GAPS}"
echo "  Auto-execute:       ${AUTO_EXECUTE}"
echo "  Dry run:            ${DRY_RUN}"
echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

# ── Step 1: Detect gaps ───────────────────────────────────────────────────────

echo "Step 1: Detecting gaps in ${INPUT_FILE} ..."
echo ""

GAP_FILE="/tmp/gaps_$(date +%s).json"

if ! python3 scripts/detect_gaps.py \
    --min-gap-size "${MIN_GAP_SIZE}" \
    --output "${GAP_FILE}" \
    "${INPUT_FILE}"; then
    echo ""
    echo "✅ Gaps detected — analyzing for backfill ..."
else
    echo ""
    echo "✅ No gaps found — data is continuous!"
    exit 0
fi

echo ""

# ── Step 2: Parse gaps and generate commands ──────────────────────────────────

echo "Step 2: Generating backfill commands ..."
echo ""

# Extract gap ranges from JSON
GAPS=$(python3 -c "
import json
import sys

with open('${GAP_FILE}') as f:
    data = json.load(f)

gaps = data['index_gaps']

# Sort by size (largest first) and take top N
gaps_sorted = sorted(gaps, key=lambda x: x['size'], reverse=True)
gaps_top = gaps_sorted[:${MAX_GAPS}]

for gap in gaps_top:
    print(f\"{gap['start']} {gap['end']} {gap['size']}\")
")

if [ -z "${GAPS}" ]; then
    echo "No gaps meet the criteria (min size: ${MIN_GAP_SIZE})"
    exit 0
fi

# Count gaps
GAP_COUNT=$(echo "${GAPS}" | wc -l | tr -d ' ')

echo "Found ${GAP_COUNT} gaps to backfill:"
echo ""

# Display gaps
echo "${GAPS}" | while IFS=' ' read -r START END SIZE; do
    echo "  • Index ${START} → ${END}  (${SIZE} entries)"
done

echo ""

# ── Step 3: Execute backfills ─────────────────────────────────────────────────

if [ "${DRY_RUN}" = true ]; then
    echo "DRY RUN MODE - Commands that would be executed:"
    echo ""
    echo "${GAPS}" | while IFS=' ' read -r START END SIZE; do
        echo "  python3 src/data/ingest_certificates_labels.py live-certs \\"
        echo "      --output \"${INPUT_FILE}\" \\"
        echo "      --start-index ${START} \\"
        echo "      --end-index ${END}"
        echo ""
    done
    exit 0
fi

if [ "${AUTO_EXECUTE}" = false ]; then
    read -p "Execute backfills for ${GAP_COUNT} gaps? [y/N] " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted"
        exit 0
    fi
fi

echo ""
echo "Starting backfill operations ..."
echo ""

GAP_NUM=0
echo "${GAPS}" | while IFS=' ' read -r START END SIZE; do
    GAP_NUM=$((GAP_NUM + 1))

    echo "────────────────────────────────────────────────────────────────────────────"
    echo "Backfilling gap ${GAP_NUM}/${GAP_COUNT}: Index ${START} → ${END} (${SIZE} entries)"
    echo "────────────────────────────────────────────────────────────────────────────"
    echo ""

    # Execute backfill
    if python3 src/data/ingest_certificates_labels.py live-certs \
        --output "${INPUT_FILE}" \
        --start-index "${START}" \
        --end-index "${END}" \
        --batch-size 256; then
        echo ""
        echo "✅ Gap ${GAP_NUM} backfilled successfully"
    else
        echo ""
        echo "❌ Gap ${GAP_NUM} backfill failed (continuing with remaining gaps)"
    fi

    echo ""
    sleep 1
done

# ── Summary ───────────────────────────────────────────────────────────────────

echo "════════════════════════════════════════════════════════════════════════════"
echo "  Backfill Complete!"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "  Processed ${GAP_COUNT} gaps"
echo ""
echo "  Next steps:"
echo "    1. Re-run gap detection to verify:"
echo "       python3 scripts/detect_gaps.py ${INPUT_FILE}"
echo ""
echo "    2. If gaps remain, run this script again:"
echo "       ./scripts/backfill_gaps.sh ${INPUT_FILE}"
echo ""
echo "    3. Update features with new data:"
echo "       ./scripts/pipeline_streaming.sh"
echo ""

# Clean up
rm -f "${GAP_FILE}"
