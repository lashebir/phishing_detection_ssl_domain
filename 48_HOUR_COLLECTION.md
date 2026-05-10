# 48-Hour Streaming Collection Guide

## Overview

This guide covers running a 48-hour CT log streaming collection to capture both **weekend and weekday** traffic patterns with real-time PhishTank + Tranco labeling.

## Why 48 Hours?

**Temporal Coverage:**
- Captures different days of the week (e.g., Saturday → Monday)
- Phishing campaigns have temporal patterns (more active on weekdays)
- Legitimate traffic varies by day (business sites quiet on weekends)

**Data Volume:**
- Expected: 800,000 - 2,000,000 certificates
- Expected: 500,000 - 1,000,000 unique domains
- Expected phishing: 50 - 500 domains (0.01-0.05% of total)
- Expected legitimate (Tranco): 5,000 - 50,000 domains (1-5%)

## Configuration

The 48-hour script runs:
- **48 iterations** × **1 hour each** = 48 hours total
- PhishTank labels refresh every hour (matches their update frequency)
- Safe Ctrl+C - progress saved after each iteration
- File sizes: ~2-4 GB total

## Quick Start

### 1. Test First (Recommended)

Verify everything works with a 2-minute test:

```bash
./scripts/test_streaming.sh
```

Expected output:
```
✅ Certificates collected: ~500
✅ Labels fetched: ~500
```

### 2. Run 48-Hour Collection

**Option A: Interactive (stay connected)**

```bash
./scripts/stream_48_hours.sh
```

You'll be prompted to confirm before starting.

**Option B: Background (recommended for long runs)**

```bash
# Run in background with nohup
nohup ./scripts/stream_48_hours.sh > logs/stream_48h.log 2>&1 &

# Get the process ID
echo $! > logs/stream_48h.pid

# Monitor progress in another terminal
./scripts/monitor_streaming.sh
```

**Option C: Screen/tmux (for SSH sessions)**

```bash
# Using screen
screen -S streaming
./scripts/stream_48_hours.sh
# Press Ctrl+A then D to detach
# screen -r streaming to reattach

# Using tmux
tmux new -s streaming
./scripts/stream_48_hours.sh
# Press Ctrl+B then D to detach
# tmux attach -t streaming to reattach
```

### 3. Monitor Progress

While collection is running, open a second terminal:

```bash
./scripts/monitor_streaming.sh
```

This shows real-time updates:
- Certificates collected
- Collection rate (certs/sec, certs/hour)
- Label distribution (phishing, legitimate, unknown)
- Latest phishing domains found

## Output Files

```
sources/raw/
├── certs_streaming_48h.jsonl   # Certificate records
└── labels_streaming_48h.jsonl  # Domain labels
```

## Monitoring Commands

### Real-time tail of certificates:

```bash
tail -f sources/raw/certs_streaming_48h.jsonl | jq -r '.domains[]' | head -20
```

### Count by label source:

```bash
cat sources/raw/labels_streaming_48h.jsonl | jq -r '.label_source' | sort | uniq -c
```

### Show phishing domains:

```bash
cat sources/raw/labels_streaming_48h.jsonl | jq -r 'select(.label_source == "phishtank") | .domain'
```

### Show collection rate:

```bash
# Total certificates
wc -l sources/raw/certs_streaming_48h.jsonl

# Certificates per hour (assuming 48 hours)
echo "scale=2; $(wc -l < sources/raw/certs_streaming_48h.jsonl) / 48" | bc
```

### File sizes:

```bash
ls -lh sources/raw/certs_streaming_48h.jsonl sources/raw/labels_streaming_48h.jsonl
```

## Expected Timeline

| Time | Event |
|------|-------|
| 0:00 | Start collection |
| 1:00 | First iteration complete (~20k certs) |
| 12:00 | Halfway point (~500k certs) |
| 24:00 | One day complete (~1M certs) |
| 48:00 | Collection complete (~2M certs) |

## Handling Interruptions

### Graceful Stop (Ctrl+C)

The script handles interrupts cleanly:
- Current iteration completes
- All data flushed to disk
- Files remain valid JSONL
- Can resume by restarting (files are appended)

### Check If Running

```bash
# Find the process
ps aux | grep "ingest_certificates_labels.py"

# Check PID file (if using background mode)
cat logs/stream_48h.pid
ps -p $(cat logs/stream_48h.pid)
```

### Stop Background Process

```bash
# Using PID file
kill $(cat logs/stream_48h.pid)

# Or find and kill
pkill -f "ingest_certificates_labels.py"
```

### Resume After Stop

Just restart the script - it appends to existing files:

```bash
./scripts/stream_48_hours.sh
# Answer 'N' when asked to delete existing files
```

## PhishTank API Key (Optional)

For higher rate limits, get a free API key:

1. Register: https://phishtank.com/api_info.php
2. Set environment variable:

```bash
export PHISHTANK_API_KEY="your_key_here"
./scripts/stream_48_hours.sh
```

Or add to your `~/.bashrc` or `~/.zshrc`:

```bash
echo 'export PHISHTANK_API_KEY="your_key_here"' >> ~/.bashrc
```

## Disk Space Check

Before starting:

```bash
# Check available space (need ~5-10 GB)
df -h .

# Clean up old files if needed
rm sources/raw/test_*.jsonl  # Remove test files
```

## Troubleshooting

### Issue: "Connection timeout"

```
WARNING: API error: timeout — retrying in 10s
```

**Solution:** Normal for slow networks. Script auto-retries. No action needed.

### Issue: "PhishTank rate limit"

```
WARNING: PhishTank download failed: 429
```

**Solution:** Using cached file. Labels may be 1 hour old. Get API key for fresh labels.

### Issue: No phishing domains

```
Labeled 50000 domains: 0 phishing, 2500 legitimate, 47500 unknown
```

**Solution:** Phishing is RARE (~0.01%). This is normal. Keep running.

### Issue: Process killed

```
Killed: 9
```

**Solution:** Out of memory. Reduce batch size:

```bash
# Edit stream_48_hours.sh, change:
--batch-size 256   # to -->   --batch-size 128
```

## After Collection Complete

### 1. Verify Data Quality

```bash
# Check label distribution
cat sources/raw/labels_streaming_48h.jsonl | jq -r '.label_source' | sort | uniq -c

# Expected output:
#  950000 unknown
#   45000 tranco
#     500 phishtank
```

### 2. Quick Stats

```bash
# Certificates
CERTS=$(wc -l < sources/raw/certs_streaming_48h.jsonl)
echo "Total certificates: ${CERTS}"

# Labels by source
jq -r '.label_source' sources/raw/labels_streaming_48h.jsonl | sort | uniq -c

# Unique domains
jq -r '.domain' sources/raw/labels_streaming_48h.jsonl | sort -u | wc -l
```

### 3. Update Feature Engineering

Modify `src/features/feature_engineering.py` to use streaming data:

```python
# Load streaming certificates and labels
df_certs = pd.read_json("sources/raw/certs_streaming_48h.jsonl", lines=True)
df_labels = pd.read_json("sources/raw/labels_streaming_48h.jsonl", lines=True)
```

### 4. Extract Features

```bash
python src/features/feature_engineering.py
```

### 5. Train Models

Open `notebooks/model_sandbox.ipynb` and update to use streaming features:

```python
# Load streaming features
df = pd.read_parquet("features_streaming.parquet")

# Optional: Filter to high-confidence labels only
df_confident = df[df["label_source"].isin(["phishtank", "tranco"])]

# Check class distribution
print(df_confident["y"].value_counts())
```

## Performance Expectations

With temporally-clean streaming data, expect:

| Metric | With Leakage (old) | Without Leakage (new) |
|--------|-------------------|----------------------|
| Accuracy | >99% (fake) | 70-85% (real) |
| Recall | >99% (fake) | 40-70% (real) |
| Precision | >99% (fake) | 5-30% (real) |
| AP (Avg Precision) | >0.99 (fake) | 0.20-0.60 (real) |

**Lower performance is GOOD** - it means you're measuring real-world difficulty!

## Data Characteristics

### Class Imbalance

Streaming data has SEVERE imbalance (realistic):

```
Phishing:    0.01-0.1%  (rare)
Legitimate:  1-5%       (Tranco top-10k)
Unknown:     95-99%     (unlabeled)
```

**Solutions:**
- Filter to `label_source in ["phishtank", "tranco"]` for high confidence
- Use `class_weight='balanced'` in models
- Optimize for recall, not accuracy
- Use PR curves, not ROC curves

### Temporal Patterns

Weekend vs weekday differences you might see:

| Day Type | Phishing Activity | Legitimate Activity |
|----------|------------------|---------------------|
| Weekend | Lower (fewer campaigns) | Lower (business sites quiet) |
| Weekday | Higher (active campaigns) | Higher (normal traffic) |

This is VALUABLE signal for temporal models!

## Estimated Costs

- **Time:** 48 hours runtime
- **Network:** ~2-4 GB download
- **Disk:** ~2-4 GB storage
- **API calls:** ~100k PhishTank lookups (free tier OK)
- **CPU:** Minimal (mostly waiting)

## Next Steps

After successful 48-hour collection:

1. ✅ Verify label quality
2. ✅ Update feature engineering
3. ✅ Retrain models with clean data
4. ✅ Compare performance with old approach
5. ✅ Analyze temporal patterns (weekend vs weekday)

## Advanced: Combining with Historical

You can train on both but test only on streaming:

```python
# Load both datasets
df_stream = pd.read_parquet("features_streaming.parquet")
df_hist = pd.read_parquet("features_historical.parquet")

# Add data source marker
df_stream["source"] = "streaming"
df_hist["source"] = "historical"

# Train on both (more data)
train = pd.concat([
    df_stream.sample(frac=0.7, random_state=42),
    df_hist  # All historical for training
])

# Test ONLY on streaming (honest evaluation)
test = df_stream.drop(train[train["source"] == "streaming"].index)

# This gives you more training data without leakage in evaluation
```

## Support

If you encounter issues:

1. Check logs: `logs/stream_48h.log`
2. Monitor: `./scripts/monitor_streaming.sh`
3. Review: `STREAMING_INGESTION.md`
