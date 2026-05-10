# 48-Hour Collection Quick Start

## ✅ Your Test Passed!

```
✅ Certificates collected: 491
✅ Labels fetched: 491
✅ PhishTank + Tranco integration working
```

## Run 48-Hour Collection

### Option 1: Foreground (Interactive)

```bash
cd /Users/leahashebir/Documents/ssl_anomaly_detection
./scripts/stream_48_hours.sh
```

Press `y` to confirm, then let it run for 48 hours.

### Option 2: Background (Recommended)

```bash
cd /Users/leahashebir/Documents/ssl_anomaly_detection

# Create logs directory (if not exists)
mkdir -p logs

# Run in background with nohup
nohup ./scripts/stream_48_hours.sh > logs/stream_48h.log 2>&1 &

# Save process ID
echo $! > logs/stream_48h.pid

# Confirm it's running
ps -p $(cat logs/stream_48h.pid)
```

### Option 3: Screen (for SSH)

```bash
cd /Users/leahashebir/Documents/ssl_anomaly_detection

# Start screen session
screen -S streaming

# Run the script
./scripts/stream_48_hours.sh

# Detach: Press Ctrl+A then D
# Reattach later: screen -r streaming
```

## Monitor Progress

**While running**, open a second terminal:

```bash
cd /Users/leahashebir/Documents/ssl_anomaly_detection
./scripts/monitor_streaming.sh
```

Shows real-time:
- Certificates collected
- Collection rate
- Label distribution
- Latest phishing domains

**Manual checks:**

```bash
# Count certificates
wc -l sources/raw/certs_streaming_48h.jsonl

# Count labels by source
cat sources/raw/labels_streaming_48h.jsonl | jq -r '.label_source' | sort | uniq -c

# Show phishing domains
cat sources/raw/labels_streaming_48h.jsonl | jq -r 'select(.label_source == "phishtank") | .domain'

# Check if still running
ps aux | grep "ingest_certificates_labels.py"
```

## Stop/Resume

**Stop gracefully:**

```bash
# If foreground: Ctrl+C

# If background:
kill $(cat logs/stream_48h.pid)
```

**Resume after stop:**

```bash
./scripts/stream_48_hours.sh
# Answer 'N' to keep existing data (appends)
```

## Expected Results

After 48 hours:

```
Certificates: 800,000 - 2,000,000
Unique domains: 500,000 - 1,000,000
Phishing (PhishTank): 50 - 500 (0.01-0.05%)
Legitimate (Tranco): 5,000 - 50,000 (1-5%)
Unknown: 95-99% (unlabeled)
```

## Configuration

- **48 iterations** × **1 hour** = 48 hours
- Labels refresh every hour
- Output: `sources/raw/certs_streaming_48h.jsonl` & `labels_streaming_48h.jsonl`
- File size: ~2-4 GB total
- Network: ~2-4 GB download

## Key Features

✅ **No temporal leakage** - Both classes from same time period
✅ **Real-time labeling** - PhishTank + Tranco every hour
✅ **Fault tolerant** - Ctrl+C safe, can resume
✅ **Weekend + weekday** - Captures temporal patterns
✅ **Progress tracking** - Saved after each iteration

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection timeout | Auto-retries, no action needed |
| PhishTank rate limit | Get API key from phishtank.com/api_info.php |
| No phishing found | Normal (rare), keep running |
| Out of memory | Reduce batch_size to 128 in script |

## Next Steps

After 48 hours complete:

```bash
# 1. Verify data
cat sources/raw/labels_streaming_48h.jsonl | jq -r '.label_source' | sort | uniq -c

# 2. Update feature engineering (use streaming files)
python src/features/feature_engineering.py

# 3. Retrain models
# Open notebooks/model_sandbox.ipynb
```

## Full Documentation

- **Detailed guide:** `48_HOUR_COLLECTION.md`
- **Streaming setup:** `STREAMING_INGESTION.md`
- **Project overview:** `CLAUDE.md`
