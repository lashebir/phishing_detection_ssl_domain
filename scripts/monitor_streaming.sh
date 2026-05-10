#!/bin/bash
#
# Monitor ongoing streaming collection
#
# Shows real-time progress of the streaming pipeline.
#

CERTS_FILE="${1:-sources/raw/certs_streaming_48h.jsonl}"
LABELS_FILE="${2:-sources/raw/labels_streaming_48h.jsonl}"

if [ ! -f "${CERTS_FILE}" ]; then
    echo "❌ Certs file not found: ${CERTS_FILE}"
    echo ""
    echo "Usage: $0 [certs_file] [labels_file]"
    echo "Example: $0 sources/raw/certs_streaming_48h.jsonl sources/raw/labels_streaming_48h.jsonl"
    exit 1
fi

echo "════════════════════════════════════════════════════════════════════════════"
echo "  Streaming Collection Monitor"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "  Files:"
echo "    Certs:  ${CERTS_FILE}"
echo "    Labels: ${LABELS_FILE}"
echo ""
echo "  Press Ctrl+C to exit monitor (collection continues in background)"
echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

while true; do
    clear
    echo "═══════════════════════════════════════════════════════════════════════════"
    echo "  Streaming Collection Monitor - $(date)"
    echo "═══════════════════════════════════════════════════════════════════════════"
    echo ""

    if [ -f "${CERTS_FILE}" ]; then
        CERT_COUNT=$(wc -l < "${CERTS_FILE}" | tr -d ' ')
        echo "  📊 Certificates Collected: ${CERT_COUNT}"

        # Calculate collection rate
        FILE_AGE_SEC=$(( $(date +%s) - $(stat -f %m "${CERTS_FILE}" 2>/dev/null || stat -c %Y "${CERTS_FILE}" 2>/dev/null || echo 0) ))
        if [ "${FILE_AGE_SEC}" -gt 0 ]; then
            RATE=$(awk "BEGIN {printf \"%.1f\", ${CERT_COUNT}/${FILE_AGE_SEC}}")
            RATE_PER_HOUR=$(awk "BEGIN {printf \"%.0f\", ${CERT_COUNT}*3600/${FILE_AGE_SEC}}")
            FILE_AGE_MIN=$(( FILE_AGE_SEC / 60 ))
            echo "  ⏱️  Collection Rate: ${RATE}/sec (~${RATE_PER_HOUR}/hour)"
            echo "  🕒 Running for: ${FILE_AGE_MIN} minutes ($(awk "BEGIN {printf \"%.1f\", ${FILE_AGE_MIN}/60}") hours)"
        fi
    else
        echo "  ⏳ Waiting for certs file to be created..."
    fi

    echo ""

    if [ -f "${LABELS_FILE}" ]; then
        LABEL_COUNT=$(wc -l < "${LABELS_FILE}" | tr -d ' ')
        echo "  🏷️  Labels Fetched: ${LABEL_COUNT}"
        echo ""

        echo "  Label Distribution:"
        cat "${LABELS_FILE}" | jq -r '.label_source' | sort | uniq -c | awk '{printf "    %10s: %7s\n", $2, $1}'

        echo ""

        PHISHING=$(cat "${LABELS_FILE}" | jq -r 'select(.label_source == "phishtank") | .domain' | wc -l | tr -d ' ')
        TRANCO=$(cat "${LABELS_FILE}" | jq -r 'select(.label_source == "tranco") | .domain' | wc -l | tr -d ' ')
        UNKNOWN=$(cat "${LABELS_FILE}" | jq -r 'select(.label_source == "unknown") | .domain' | wc -l | tr -d ' ')

        if [ "${LABEL_COUNT}" -gt 0 ]; then
            PHISH_PCT=$(awk "BEGIN {printf \"%.3f\", 100.0*${PHISHING}/${LABEL_COUNT}}")
            TRAN_PCT=$(awk "BEGIN {printf \"%.2f\", 100.0*${TRANCO}/${LABEL_COUNT}}")
            UNK_PCT=$(awk "BEGIN {printf \"%.2f\", 100.0*${UNKNOWN}/${LABEL_COUNT}}")

            echo "  Class Distribution:"
            echo "    🎯 Phishing:   ${PHISHING} (${PHISH_PCT}%)"
            echo "    ✅ Legitimate: ${TRANCO} (${TRAN_PCT}%)"
            echo "    ❔ Unknown:    ${UNKNOWN} (${UNK_PCT}%)"
        fi

        if [ "${PHISHING}" -gt 0 ]; then
            echo ""
            echo "  🚨 Latest Phishing Domains (last 5):"
            cat "${LABELS_FILE}" | jq -r 'select(.label_source == "phishtank") | .domain' | tail -5 | sed 's/^/    ⚠️  /'
        fi
    else
        echo "  ⏳ Waiting for labels file to be created..."
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════════════════════"
    echo "  Refreshing in 10 seconds... (Ctrl+C to exit)"
    echo "═══════════════════════════════════════════════════════════════════════════"

    sleep 10
done
