# Streaming CT Log Ingestion with Real-Time Labeling

## Problem: Temporal Data Leakage

**Previous Approach:**
- Live data (April 2026): 100% legitimate (y=0)
- Historical data (various years): 100% phishing (y=1)
- **Result:** Model learned "old vs new certs" NOT "phishing vs legitimate"
- Features like `validity_days`, `is_letsencrypt` encoded temporal patterns

## Solution: Stream + Label in Real-Time

**New Approach:**
- Collect certificates from CT log in real-time
- Label domains IMMEDIATELY using:
  - **PhishTank**: Verified phishing domains → y=1
  - **Tranco top-10k**: Legitimate popular domains → y=0
  - **Unknown**: Everything else → y=0 (label_source="unknown")

**Benefits:**
- ✅ Both classes from SAME time period
- ✅ No temporal leakage
- ✅ Real-world class distribution
- ✅ Can filter by label_source later

## Quick Start

### Run the streaming pipeline:

```bash
# Default: 5 iterations × 15 minutes = 75 minutes total
./scripts/stream_with_labels.sh

# Customize duration and iterations
./scripts/stream_with_labels.sh 1800 10  # 10 iterations × 30 min
```

### Outputs:

- **sources/raw/certs_streaming.jsonl** - Certificate records with metadata
- **sources/raw/labels_streaming.jsonl** - Domain labels (y=0 or y=1)

### Label Distribution:

Based on typical CT log traffic:
- ~0.01-0.1% phishing (PhishTank)
- ~1-5% legitimate (Tranco top-10k)
- ~95-99% unknown (unlabeled)

**Note:** "Unknown" domains are labeled y=0 but have `label_source="unknown"`. You can filter these out or treat as low-confidence legitimate.

## Usage Examples

### 1. Basic Streaming (Recommended)

```bash
./scripts/stream_with_labels.sh
```

Runs for 5 iterations × 15 minutes = 75 minutes, collecting both certs and labels.

### 2. Custom Duration

```bash
# Run for 2 hours straight (1 iteration × 7200 seconds)
python src/data/ingest_certificates_labels.py live \
    --certs sources/raw/certs_streaming.jsonl \
    --labels sources/raw/labels_streaming.jsonl \
    --duration 7200 \
    --iterations 1
```

### 3. Overnight Collection

```bash
# Run for 8 hours (8 iterations × 1 hour)
python src/data/ingest_certificates_labels.py live \
    --certs sources/raw/certs_overnight.jsonl \
    --labels sources/raw/labels_overnight.jsonl \
    --duration 3600 \
    --iterations 8
```

### 4. Check PhishTank API Key (Optional)

PhishTank allows higher rate limits with a free API key:

```bash
# Register at: https://phishtank.com/api_info.php
export PHISHTANK_API_KEY="your_key_here"

# Or pass directly:
python src/data/ingest_certificates_labels.py live \
    --api-key "your_key_here" \
    --certs sources/raw/certs.jsonl \
    --labels sources/raw/labels.jsonl
```

## Data Processing Pipeline

After collecting streaming data:

### 1. Feature Engineering

```bash
python src/features/feature_engineering.py
```

This will:
- Load `certs_streaming.jsonl` and `labels_streaming.jsonl`
- Extract domain and SSL features
- Join with labels
- Output `features.parquet` with y labels

### 2. Model Training

Run `notebooks/model_sandbox.ipynb` with the new features:

```python
# Load features
df = pd.read_parquet("features.parquet")

# Filter to high-confidence labels only (optional)
df_confident = df[df["label_source"].isin(["phishtank", "tranco"])]

# Or use all data (treat unknown as legitimate)
df_all = df  # includes label_source="unknown" as y=0
```

## Label Source Filtering

The `label_source` field lets you control confidence:

```python
# High confidence only: PhishTank + Tranco
df_hc = df[df["label_source"].isin(["phishtank", "tranco"])]
# Expected: ~1-5% of data, but high quality

# Include unknown as legitimate (more data, lower precision)
df_all = df  # All domains
# Expected: ~95-99% of data

# Phishing only (for analysis)
df_phishing = df[df["label_source"] == "phishtank"]
```

## Monitoring

While streaming is running, you can monitor progress:

```bash
# Watch cert collection in real-time
tail -f sources/raw/certs_streaming.jsonl | jq -r '.domains[]' | head -20

# Count certificates collected
wc -l sources/raw/certs_streaming.jsonl

# Count labels by source
cat sources/raw/labels_streaming.jsonl | jq -r '.label_source' | sort | uniq -c
```

Example output:
```
  15234 unknown
    456 tranco
     12 phishtank
```

## Troubleshooting

### PhishTank rate limit

```
WARNING: PhishTank download failed: 429 Client Error
```

**Solution:** Register for free API key at https://phishtank.com/api_info.php

### CT log connection timeout

```
WARNING: API error: timeout — retrying in 10s
```

**Solution:** Normal for slow networks. Script auto-retries with backoff.

### No phishing domains found

```
Labeled 5000 domains: 0 phishing, 250 legitimate (Tranco), 4750 unknown
```

**Solution:** Phishing is rare (~0.01%). Run for longer duration or accept low phishing rate.

## Architecture: How It Works

### Phase 1: Collect Certificates (15 min)

```
CT Log → Get entries → Parse → Write to certs_streaming.jsonl
         (batch=256)            (domains, issuer, timestamps, etc.)
```

### Phase 2: Label Domains (1-2 min)

```
certs_streaming.jsonl → Extract domains → Lookup labels → Write to labels_streaming.jsonl
                                           ↓
                                        PhishTank (y=1)
                                        Tranco (y=0)
                                        Unknown (y=0)
```

### Repeat for N iterations

## Expected Results

After running for 1-2 hours:

| Metric | Value |
|--------|-------|
| Certificates collected | 50,000 - 200,000 |
| Unique domains | 30,000 - 100,000 |
| Phishing domains (PhishTank) | 5 - 50 |
| Legitimate domains (Tranco) | 500 - 5,000 |
| Unknown domains | 25,000 - 95,000 |

**Note:** Phishing is RARE in live CT logs. You may need to:
1. Run for many hours to collect enough phishing samples
2. Combine with historical phishing (but keep them separate in analysis)
3. Use techniques like SMOTE for class balancing

## Comparison: Old vs New Approach

| Aspect | Old (Temporal Leakage) | New (Streaming + Labeling) |
|--------|------------------------|----------------------------|
| Data source | Live (2026) + Historical (various) | Live CT log only (2026) |
| Labeling | After-the-fact | Real-time |
| Live data labels | All y=0 | Mixed: PhishTank, Tranco, unknown |
| Historical labels | All y=1 | N/A (not used) |
| Temporal features | Leaked class information | No leakage |
| Class distribution | Perfect separation | Real-world (~0.01% phishing) |
| Model performance | Fake (99%+ from leakage) | Real (expect 70-85%) |

## Next Steps

1. **Run streaming collection** for 2-4 hours
2. **Check label distribution** (should have some PhishTank hits)
3. **Update feature engineering** to use streaming data
4. **Retrain models** in model_sandbox.ipynb
5. **Compare performance** with old approach (expect lower but REAL metrics)

## Advanced: Combining Sources

You can combine streaming data with historical, but keep them separate:

```python
# Load streaming (no temporal leakage)
df_stream = pd.read_parquet("features_streaming.parquet")
df_stream["data_source"] = "streaming"

# Load historical (for training only, not evaluation)
df_hist = pd.read_parquet("features_historical.parquet")
df_hist["data_source"] = "historical"

# Train on both, test on streaming only
train = pd.concat([df_stream.sample(frac=0.7), df_hist])
test = df_stream.drop(train.index)
```

This gives you more training data while keeping evaluation honest.
