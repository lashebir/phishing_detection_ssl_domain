#!/bin/bash
#
# Stream CT logs with real-time PhishTank + Tranco labeling
#
# This solves the data leakage problem by creating BOTH classes
# (phishing and legitimate) in the SAME time period.
#
# Usage:
#   ./scripts/stream_with_labels.sh              # Run with defaults (5 iterations × 15min)
#   ./scripts/stream_with_labels.sh --duration 1800 --iterations 10  # Customize
#

set -e

cd "$(dirname "$0")/.."

DURATION=${1:-900}      # Default: 15 minutes per batch
ITERATIONS=${2:-5}      # Default: 5 iterations

CERTS_FILE="sources/raw/certs_streaming.jsonl"
LABELS_FILE="sources/raw/labels_streaming.jsonl"

echo "════════════════════════════════════════════════════════════════════════════"
echo "  Streaming CT Log Ingestion with PhishTank + Tranco Labeling"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "  Mode: Integrated streaming pipeline"
echo "  Duration per batch: ${DURATION}s ($(($DURATION / 60)) minutes)"
echo "  Iterations: ${ITERATIONS}"
echo "  Output certs: ${CERTS_FILE}"
echo "  Output labels: ${LABELS_FILE}"
echo ""
echo "  Label sources:"
echo "    - PhishTank: Verified phishing domains (y=1)"
echo "    - Tranco top-10k: Legitimate domains (y=0)"
echo "    - Unknown: Everything else (y=0, label_source='unknown')"
echo ""
echo "  Press Ctrl+C to stop early"
echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

python3 src/data/ingest_certificates_labels.py live \
    --certs "${CERTS_FILE}" \
    --labels "${LABELS_FILE}" \
    --duration "${DURATION}" \
    --iterations "${ITERATIONS}" \
    --batch-size 256 \
    --poll-delay 1.0

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "  Streaming Complete!"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "  Files created:"
echo "    Certificates: ${CERTS_FILE}"
echo "    Labels:       ${LABELS_FILE}"
echo ""
echo "  Next steps:"
echo "    1. Run feature engineering:"
echo "       python src/features/feature_engineering.py"
echo ""
echo "    2. Train models in notebooks/model_sandbox.ipynb"
echo ""
echo "  Key advantage:"
echo "    ✅ Both classes (phishing + legitimate) from SAME time period"
echo "    ✅ No temporal leakage!"
echo "    ✅ Real-world distribution"
echo ""
