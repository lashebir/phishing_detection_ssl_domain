#!/bin/bash
#
# Quick test of streaming ingestion pipeline (2 minutes)
#
# This runs a SHORT collection to verify everything works before
# committing to a long-running job.
#

set -e

cd "$(dirname "$0")/.."

echo "════════════════════════════════════════════════════════════════════════════"
echo "  Testing Streaming Ingestion (2 minute test)"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

CERTS_FILE="sources/raw/test_certs.jsonl"
LABELS_FILE="sources/raw/test_labels.jsonl"

# Clean up old test files
rm -f "${CERTS_FILE}" "${LABELS_FILE}"

echo "  Output:"
echo "    Certs:  ${CERTS_FILE}"
echo "    Labels: ${LABELS_FILE}"
echo ""
echo "  Running 1 iteration × 120 seconds (2 minutes) ..."
echo ""

python3 src/data/ingest_certificates_labels.py live \
    --certs "${CERTS_FILE}" \
    --labels "${LABELS_FILE}" \
    --duration 120 \
    --iterations 1 \
    --batch-size 256 \
    --poll-delay 1.0

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "  Test Results"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

if [ -f "${CERTS_FILE}" ]; then
    CERT_COUNT=$(wc -l < "${CERTS_FILE}" | tr -d ' ')
    echo "  ✅ Certificates collected: ${CERT_COUNT}"

    # Sample a few domains
    echo ""
    echo "  Sample domains:"
    cat "${CERTS_FILE}" | jq -r '.domains[]' | head -10 | sed 's/^/    - /'
else
    echo "  ❌ No certs file created!"
    exit 1
fi

echo ""

if [ -f "${LABELS_FILE}" ]; then
    LABEL_COUNT=$(wc -l < "${LABELS_FILE}" | tr -d ' ')
    echo "  ✅ Labels fetched: ${LABEL_COUNT}"

    # Count by label source
    echo ""
    echo "  Label distribution:"
    cat "${LABELS_FILE}" | jq -r '.label_source' | sort | uniq -c | sed 's/^/    /'

    # Show phishing domains if any
    PHISHING_COUNT=$(cat "${LABELS_FILE}" | jq -r 'select(.label_source == "phishtank") | .domain' | wc -l | tr -d ' ')
    if [ "${PHISHING_COUNT}" -gt 0 ]; then
        echo ""
        echo "  🎯 Found ${PHISHING_COUNT} phishing domain(s):"
        cat "${LABELS_FILE}" | jq -r 'select(.label_source == "phishtank") | .domain' | sed 's/^/    ⚠️  /'
    else
        echo ""
        echo "  ℹ️  No phishing domains found in this short test"
        echo "     (Phishing is rare, ~0.01% of traffic)"
    fi

    # Show Tranco domains if any
    TRANCO_COUNT=$(cat "${LABELS_FILE}" | jq -r 'select(.label_source == "tranco") | .domain' | wc -l | tr -d ' ')
    if [ "${TRANCO_COUNT}" -gt 0 ]; then
        echo ""
        echo "  ✅ Found ${TRANCO_COUNT} Tranco top-10k domain(s):"
        cat "${LABELS_FILE}" | jq -r 'select(.label_source == "tranco") | .domain' | head -5 | sed 's/^/    ✓  /'
    fi
else
    echo "  ❌ No labels file created!"
    exit 1
fi

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "  Test Passed! ✅"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "  Next steps:"
echo "    1. Run full collection:"
echo "       ./scripts/stream_with_labels.sh"
echo ""
echo "    2. Or customize duration:"
echo "       ./scripts/stream_with_labels.sh 1800 10  # 10 × 30min"
echo ""
