#!/bin/bash
#
# 48-Hour Streaming Collection (Non-Interactive Background Version)
#
# This version runs without prompts - safe for nohup/background execution.
#

set -e

cd "$(dirname "$0")/.."

DURATION=3600      # 1 hour per iteration
ITERATIONS=48      # 48 iterations = 48 hours
TOTAL_HOURS=$((DURATION * ITERATIONS / 3600))

CERTS_FILE="sources/raw/certs_streaming_48h.jsonl"
LABELS_FILE="sources/raw/labels_streaming_48h.jsonl"

echo "════════════════════════════════════════════════════════════════════════════"
echo "  48-Hour Streaming CT Log Collection (Background Mode)"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "  Configuration:"
echo "    Duration per iteration: ${DURATION}s ($(($DURATION / 60)) minutes)"
echo "    Total iterations: ${ITERATIONS}"
echo "    Total runtime: ${TOTAL_HOURS} hours"
echo ""
echo "  Start time: $(date)"
echo "  Estimated completion: $(date -v+${TOTAL_HOURS}H 2>/dev/null || date -d "+${TOTAL_HOURS} hours" 2>/dev/null || echo "~48 hours from now")"
echo ""
echo "  Output files:"
echo "    Certs:  ${CERTS_FILE}"
echo "    Labels: ${LABELS_FILE}"
echo ""
echo "  Mode: Non-interactive (appends to existing files if present)"
echo "  Label refresh: Every hour (matches PhishTank update frequency)"
echo "  Recovery: Ctrl+C is safe - progress saved after each iteration"
echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

# Check if files already exist and show info
if [ -f "${CERTS_FILE}" ]; then
    EXISTING_CERTS=$(wc -l < "${CERTS_FILE}" | tr -d ' ')
    echo "ℹ️  Found existing certs file with ${EXISTING_CERTS} records - will append"
fi

if [ -f "${LABELS_FILE}" ]; then
    EXISTING_LABELS=$(wc -l < "${LABELS_FILE}" | tr -d ' ')
    echo "ℹ️  Found existing labels file with ${EXISTING_LABELS} records - will append"
fi

echo ""
echo "🚀 Starting 48-hour collection..."
echo ""

# Run the pipeline (no prompts, will append if files exist)
python3 src/data/ingest_certificates_labels.py live \
    --certs "${CERTS_FILE}" \
    --labels "${LABELS_FILE}" \
    --duration "${DURATION}" \
    --iterations "${ITERATIONS}" \
    --batch-size 256 \
    --poll-delay 1.0

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "  48-Hour Collection Complete! ✅"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "  End time: $(date)"
echo ""

# Show statistics
if [ -f "${CERTS_FILE}" ] && [ -f "${LABELS_FILE}" ]; then
    CERT_COUNT=$(wc -l < "${CERTS_FILE}" | tr -d ' ')
    LABEL_COUNT=$(wc -l < "${LABELS_FILE}" | tr -d ' ')

    echo "  Collection Statistics:"
    echo "    Certificates: ${CERT_COUNT}"
    echo "    Labels: ${LABEL_COUNT}"
    echo ""

    echo "  Label Distribution:"
    cat "${LABELS_FILE}" | jq -r '.label_source' | sort | uniq -c | awk '{printf "    %10s: %s\n", $2, $1}'

    echo ""

    PHISHING_COUNT=$(cat "${LABELS_FILE}" | jq -r 'select(.label_source == "phishtank") | .domain' | wc -l | tr -d ' ')
    TRANCO_COUNT=$(cat "${LABELS_FILE}" | jq -r 'select(.label_source == "tranco") | .domain' | wc -l | tr -d ' ')
    UNKNOWN_COUNT=$(cat "${LABELS_FILE}" | jq -r 'select(.label_source == "unknown") | .domain' | wc -l | tr -d ' ')

    echo "  Class Distribution:"
    echo "    Phishing (PhishTank): ${PHISHING_COUNT} ($(awk "BEGIN {printf \"%.2f\", 100.0*${PHISHING_COUNT}/${LABEL_COUNT}}")%)"
    echo "    Legitimate (Tranco):  ${TRANCO_COUNT} ($(awk "BEGIN {printf \"%.2f\", 100.0*${TRANCO_COUNT}/${LABEL_COUNT}}")%)"
    echo "    Unknown:              ${UNKNOWN_COUNT} ($(awk "BEGIN {printf \"%.2f\", 100.0*${UNKNOWN_COUNT}/${LABEL_COUNT}}")%)"
    echo ""

    if [ "${PHISHING_COUNT}" -gt 0 ]; then
        echo "  🎯 Phishing Domains Captured:"
        cat "${LABELS_FILE}" | jq -r 'select(.label_source == "phishtank") | .domain' | head -20 | sed 's/^/    ⚠️  /'
        if [ "${PHISHING_COUNT}" -gt 20 ]; then
            echo "    ... and $((PHISHING_COUNT - 20)) more"
        fi
        echo ""
    fi
fi

echo "  Files saved:"
echo "    ${CERTS_FILE}"
echo "    ${LABELS_FILE}"
echo ""
