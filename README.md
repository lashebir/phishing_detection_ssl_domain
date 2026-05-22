# SSL/TLS Certificate Anomaly Detection for Phishing

Real-time phishing detection using Certificate Transparency (CT) logs and machine learning. This system monitors newly issued SSL/TLS certificates to identify potential phishing domains before they can be used in attacks.

## Project Goal

Detect phishing websites by analyzing patterns in SSL/TLS certificates as they're issued, leveraging:
- **Certificate Transparency logs** for real-time certificate issuance data
- **Domain-based features** (entropy, brand similarity, TLD risk, keyword presence)
- **Certificate metadata** (issuer, validity period, organization fields)
- **Temporal patterns** (time series analysis of certificate issuance)

**Key Innovation**: Time-series aware phishing detection that maintains temporal integrity by separating historical training data from live streaming data.

---
## Personal Note

Before diving into the technical aspects, I wanted to discuss my experience a bit. This has been a deeply insightful project. It has illustrated how time sensitive data must be controlled and studied properly for an accurate analysis, especially when it gives us overly optimistic results. In machine learning, some of the strongest insights come when we question the data and challenge initial assumptions, especially when working with complicated datasets. This project also gave me stronger insight into key cybersecurity features and trends-- I am a big fan of learning about new domains in action, going beyond research materials and studying actual trends through EDA & machine learning! Please feel free to send any questions to ltashebir77@gmail.com or on my [LinkedIn](https://www.linkedin.com/in/leah-ashebir/).

---

## Data Sources

### Primary Data Streams

| Source | Purpose | Update Frequency | Volume |
|--------|---------|------------------|--------|
| **Google Argon CT Log** | Real-time certificate issuance | Continuous (~50 certs/sec) | Streaming |
| **PhishTank** | Verified phishing domain labels | Hourly | ~50-200 new domains/hour |
| **Tranco Top-1M** | Legitimate domain labels | Daily | Top 10K used for training |
| **crt.sh** | Historical certificate lookups | On-demand | ~10 certs/domain |

### Data Pipeline Flow

```
┌─────────────────┐
│  CT Logs (Live) │──┐
└─────────────────┘  │
                     ├──► Feature Engineering ──► Model Training ──► Dashboard
┌─────────────────┐  │         (dbt + DuckDB)      (XGBoost)      (Streamlit)
│  PhishTank      │──┤
│  Labels         │  │
└─────────────────┘  │
                     │
┌─────────────────┐  │
│  Historical     │──┘
│  Certs (crt.sh) │
└─────────────────┘
```

---

## Architecture

### Current Stack (Production-Ready)

**Data Collection**
- **Live Streaming**: Python script polling Google CT log API (RFC 6962)
- **Historical Backfill**: crt.sh queries for known phishing domains
- **Label Aggregation**: PhishTank CSV + Tranco top-1M integration
- **Gap Handling**: Automated backfill with continuity tracking

**Feature Engineering**
- **Storage**: DuckDB (in-process OLAP database)
- **Transformation**: dbt (SQL-based feature pipelines)
- **Features**: 10+ engineered features per certificate
  - Domain entropy, subdomain count, TLD risk
  - Brand Levenshtein distance (20+ brands)
  - Certificate metadata (issuer, validity, org presence)

**Machine Learning**
- **Model**: XGBoost gradient boosting classifier
- **Training**: Stratified split with temporal awareness
- **Metrics**: Precision-recall curves, feature importance
- **Deployment**: Joblib serialization for offline inference

**Visualization**
- **Framework**: Streamlit (interactive web dashboard)
- **Charts**: Plotly (time series, distributions, PR curves)
- **Pages**: Streaming stats, model performance, data quality, drift detection

### Aspirational Stack (Streaming Architecture)

**Real-Time Streaming** (In Development)
```
CT Log API ──► Kafka Topic ──► Stream Processor ──► Feature Store
                (confluent)      (Kafka Streams)     (Redis/RocksDB)
                                                            │
                                                            ▼
                                                    Online Inference
                                                       (XGBoost)
                                                            │
                                                            ▼
                                                    Alert Dashboard
                                                    (Streamlit + WebSocket)
```

**Planned Enhancements**
- **Kafka Streams**: Replace batch polling with event-driven ingestion
- **Online Feature Store**: Redis for low-latency feature serving
- **Incremental Training**: Update model with new labels without full retrain
- **Alert System**: Real-time notifications for high-confidence phishing certs
- **A/B Testing**: Multi-model deployment with champion/challenger framework

---

## 🛠️ Tech Stack

### Core Dependencies

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Language** | Python | 3.10+ | All data processing and ML |
| **Data Warehouse** | DuckDB | Latest | In-process analytics database |
| **ETL Framework** | dbt | Latest | SQL-based feature pipelines |
| **ML Framework** | XGBoost | ≥2.0.0 | Gradient boosting classifier |
| **Dashboard** | Streamlit | Latest | Interactive web UI |
| **Visualization** | Plotly | Latest | Interactive charts |
| **CT Log Client** | Requests + cryptography | Latest | Certificate parsing |

### Python Package Requirements

See `requirements.txt` for complete list. Key dependencies:

**Data Collection**
- `requests` - HTTP client for CT log API
- `cryptography` - X.509 certificate parsing
- `pandas` - Data manipulation

**Feature Engineering**
- `dbt-duckdb` - dbt integration for DuckDB
- `python-Levenshtein` - Brand similarity features
- `tldextract` - TLD parsing and risk scoring
- `pyarrow` - Parquet file I/O

**Machine Learning**
- `xgboost>=2.0.0` - Gradient boosting
- `scikit-learn>=1.3.0` - Preprocessing and metrics
- `joblib>=1.3.0` - Model serialization

**Visualization**
- `streamlit` - Dashboard framework
- `plotly` - Interactive charts
- `matplotlib` + `seaborn` - Static plots

**Optional**
- `confluent_kafka` - For future Kafka integration
- `jupyter` - Notebook-based exploration

---

## Installation

### Prerequisites

**Required**
- Python 3.10 or higher
- pip or conda package manager

**Platform-Specific (for XGBoost)**
- **macOS**: `brew install libomp`
- **Windows**: OpenMP comes with Visual Studio C++ Build Tools
- **Linux**: `sudo apt-get install libomp-dev` (Ubuntu/Debian)

### Step 1: Clone Repository

```bash
git clone <repository-url>
cd ssl_anomaly_detection
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# Using venv
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
# venv\Scripts\activate   # Windows

# OR using conda
conda create -n ssl-phishing python=3.10
conda activate ssl-phishing
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

**macOS users**: If XGBoost installation fails:
```bash
# Install OpenMP library
brew install libomp

# Then retry pip install
pip install -r requirements.txt
```

**Windows users**: If you encounter build errors:
```bash
# Install Visual Studio Build Tools first
# Download from: https://visualstudio.microsoft.com/downloads/
# Then install C++ build tools

pip install -r requirements.txt
```

### Step 4: Verify Installation

```bash
# Test imports
python -c "import xgboost; import streamlit; import duckdb; print('✅ All core dependencies installed')"

# Check dbt installation
dbt --version
```

---

<!-- ## Quick Start

### Option 1: 48-Hour Streaming Collection (Recommended)

Collect real-time data with automatic gap tracking and label refresh:

```bash
# Start streaming (runs for 48 hours with hourly iterations)
./scripts/stream_48_hours.sh

# In another terminal, monitor progress
tail -f sources/raw/stream_sessions.log

# After collection, process features and train model
./scripts/pipeline_streaming.sh
```

**What this does:**
1. Collects ~200K certificates from live CT log
2. Refreshes PhishTank labels every hour
3. Tracks session start/stop for gap analysis
4. Generates streaming-only features
5. Trains XGBoost model on collected data

### Option 2: Historical Backfill (2 Weeks)

Collect historical data for time series analysis:

```bash
# Collect 2 weeks of historical data (sampled at 1000 certs/hour)
python scripts/two_week_historical_backfill.py

# Resume if interrupted
python scripts/two_week_historical_backfill.py --resume

# Custom date range
python scripts/two_week_historical_backfill.py \
    --start 2026-05-01 \
    --end 2026-05-15
```

**Expected output:**
- ~336K certificates (2 weeks × 24 hours × 1000 certs/hour)
- Full temporal coverage for time series analysis
- Saved to `data/timeseries/certs_historical.jsonl`

### Option 3: Quick Demo (Use Pre-Collected Data)

If you have existing data files:

```bash
# 1. Load data into DuckDB
python scripts/load_data_to_duckdb.py \
    --db feature_store.duckdb \
    --certs sources/raw/certs_streaming_48h.jsonl \
    --labels sources/raw/labels_streaming_48h.jsonl

# 2. Run dbt feature pipeline
dbt seed --profiles-dir .
dbt run --profiles-dir .

# 3. Export features
python -c "
import duckdb
con = duckdb.connect('feature_store.duckdb')
con.execute('COPY (SELECT * FROM main_final.features) TO \"features.parquet\" (FORMAT PARQUET)')
con.close()
"

# 4. Train model
python scripts/train_xgboost.py \
    --input features.parquet \
    --output src/models/xgb_model.pkl -->

<!-- # 5. Launch dashboard
streamlit run src/data/dashboard_streaming.py
``` -->

---

## Project Structure

```
ssl_anomaly_detection/
├── src/
│   ├── data/                    # Data ingestion scripts
│   │   ├── ingest_certificates_labels.py  # Unified ingestion (6 modes)
│   │   └── dashboard_streaming.py         # Streamlit dashboard
│   ├── features/                # Feature engineering (dbt models in models/)
│   └── models/                  # Trained model artifacts (.gitignored)
│
├── scripts/
│   ├── stream_48_hours.sh              # 48-hour streaming collection
│   ├── two_week_historical_backfill.py # Historical data collection
│   ├── pipeline_streaming.sh           # End-to-end feature + training pipeline
│   ├── detect_gaps.py                  # Gap detection utility
│   ├── backfill_gaps.sh                # Automated gap filling
│   ├── timeseries_gap_fill.py          # Time series gap handling
│   ├── mark_session_gaps.py            # Session-based gap analysis
│   ├── train_xgboost.py                # Model training script
│   └── load_data_to_duckdb.py          # DuckDB data loader
│
├── requirements.txt             # Python dependencies
├── dbt_project.yml             # dbt configuration
├── profiles.yml                # DuckDB connection config
└── README.md                   # This file
```

---

## Key Features

### 1. Temporal Integrity
- **Separate data streams**: Historical training data never mixes with live streaming
- **Gap tracking**: Session logs distinguish expected vs. unexpected downtime
- **Backfill support**: Automatically detect and fill missing CT log ranges

### 2. Production-Ready Data Pipeline
- **Fault tolerance**: Resume interrupted collections with state files
- **Scalability**: DuckDB handles millions of rows with SQL-based transforms
- **Modularity**: 6 ingestion modes in single unified script
- **Observability**: Real-time stats, progress tracking, gap detection

### 3. Rich Feature Engineering
- **10+ features** computed via dbt SQL models
- **Brand similarity**: Levenshtein distance to 20+ known brands
- **TLD risk scoring**: Tiered risk (trust/neutral/high-risk)
- **Temporal features**: Hour-of-day, day-of-week patterns
- **Certificate metadata**: Issuer reputation, validity duration

### 4. Interactive Dashboard
- **Real-time metrics**: Streaming collection status
- **Model performance**: PR curves, threshold optimization
- **Data quality**: Coverage analysis, gap visualization
- **Drift detection**: Distribution shifts over time

### 5. Gap Handling & Recovery
- **Automated detection**: Find missing cert_index ranges
- **One-command backfill**: `./scripts/backfill_gaps.sh <file>`
- **Session tracking**: Distinguish pipeline downtime from data loss
- **Time series filling**: Explicit gap markers for aggregations

---

<!-- ## Documentation -->

<!-- - **Inline Documentation** - All scripts include detailed docstrings and usage examples -->

<!-- --- -->

## 🔧 Common Commands

<!-- ### Data Collection

```bash
# Streaming collection (48 hours)
./scripts/stream_48_hours.sh

# Historical backfill (2 weeks)
python scripts/two_week_historical_backfill.py

# Single collection iteration (15 minutes)
python src/data/ingest_certificates_labels.py live \
    --certs sources/raw/certs_fallback.jsonl \
    --labels sources/raw/phishtank_labels.jsonl \
    --duration 900
```

### Gap Detection & Recovery

```bash
# Detect gaps
python scripts/detect_gaps.py sources/raw/certs_streaming_48h.jsonl

# Auto-backfill gaps
./scripts/backfill_gaps.sh --auto sources/raw/certs_streaming_48h.jsonl

# Fill time series gaps
python scripts/timeseries_gap_fill.py features.parquet --freq 1H --aggregate
```

### Feature Engineering

```bash
# Full pipeline (load → dbt → export → train)
./scripts/pipeline_streaming.sh

# Manual steps
python scripts/load_data_to_duckdb.py --db feature_store.duckdb \
    --certs sources/raw/certs_streaming_48h.jsonl \
    --labels sources/raw/labels_streaming_48h.jsonl

dbt seed --profiles-dir .
dbt run --profiles-dir .
```

### Model Training

```bash
# Train XGBoost model
python scripts/train_xgboost.py \
    --input features.parquet \
    --output src/models/xgb_model.pkl

# Add predictions to features
python scripts/add_predictions_to_features.py \
    --features features.parquet \
    --model src/models/xgb_model.pkl
``` -->

### Dashboard

```bash
# Launch Streamlit dashboard
streamlit run src/data/dashboard_streaming.py

# Access at http://localhost:8501
```

---

## 🐛 Troubleshooting

### XGBoost Installation Fails

**macOS**:
```bash
brew install libomp
export LDFLAGS="-L/opt/homebrew/opt/libomp/lib"
export CPPFLAGS="-I/opt/homebrew/opt/libomp/include"
pip install xgboost
```

**Windows**: Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/) with C++ support

### DuckDB Database Locked

If you see "database is locked" errors:
```bash
# Close all Python processes
pkill -f python

# Remove lock file
rm feature_store.duckdb.wal
```

### PhishTank Rate Limiting

Register for a free API key: https://phishtank.com/api_info.php

```bash
# Set environment variable
export PHISHTANK_API_KEY="your-key-here"

# Or pass to script
python src/data/ingest_certificates_labels.py live --api-key "your-key-here"
```

### Streamlit Shows "No data found"

Ensure features file exists and has streaming data:
```bash
# Check file exists
ls -lh features_streaming.parquet

# Verify data source
python -c "
import pandas as pd
df = pd.read_parquet('features.parquet')
print(df['data_source'].value_counts())
"
```

### Gap Backfill Shows "No entries returned"

The CT log may not have data for that index range (out of bounds):
```bash
# Check current tree size
curl -s https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1/get-sth | jq .tree_size

# Only backfill indices less than tree_size
```

---

## 🎓 Learning Resources

### Certificate Transparency
- [RFC 6962](https://tools.ietf.org/html/rfc6962) - Certificate Transparency specification
- [Google CT Log Monitor](https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1/get-sth) - Argon log status
- [Certificate Transparency Overview](https://certificate.transparency.dev/)

### Phishing Detection
- [PhishTank](https://phishtank.com/) - Community-verified phishing database
- [Tranco List](https://tranco-list.eu/) - Research-oriented top sites ranking

### dbt + DuckDB
- [dbt Documentation](https://docs.getdbt.com/)
- [DuckDB Documentation](https://duckdb.org/docs/)
- [dbt-duckdb Adapter](https://github.com/duckdb/dbt-duckdb)

---

## 🚧 Roadmap

### Phase 1: Core Pipeline (Complete ✅)
- [x] CT log streaming ingestion
- [x] PhishTank + Tranco label integration
- [x] dbt-based feature engineering
- [x] XGBoost model training
- [x] Streamlit dashboard
- [x] Gap detection and backfill

### Phase 2: Production Hardening (In Progress)
- [x] Session logging for gap analysis
- [x] Automated backfill scripts
- [x] Time series gap filling
- [ ] Comprehensive test suite
- [ ] CI/CD pipeline
- [ ] Docker containerization

### Phase 3: Real-Time Streaming (Planned)
- [ ] Kafka integration for event streaming
- [ ] Online feature store (Redis)
- [ ] Real-time model inference
- [ ] Alert system (email/Slack/webhook)
- [ ] Incremental model updates

### Phase 4: Advanced Analytics (Future)
- [ ] Temporal pattern analysis (prophet/statsmodels)
- [ ] Network-based features (ASN, IP reputation)
- [ ] Ensemble models (XGBoost + LightGBM + Neural Net)
- [ ] Explainability (SHAP values)
- [ ] A/B testing framework

---

## 📝 Environment Variables

Optional configuration via environment variables:

```bash
# PhishTank API (recommended for production)
export PHISHTANK_API_KEY="your-api-key"

# CT Log URL (default: Google Argon 2026h1)
export CT_LOG_URL="https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1"

# Output directories
export OUTPUT_DIR="sources/raw"
export MODEL_DIR="src/models"
```

---

## Contributions

Contributions welcome! Areas of interest:
- Additional CT log sources (Cloudflare, Let's Encrypt)
- New features (WHOIS data, DNS records, page content)
- Model improvements (deep learning, ensemble methods)
- Dashboard enhancements (real-time updates, alerting)
- Documentation and examples

---

## Acknowledgments

- **Google Certificate Transparency** - CT log infrastructure
- **PhishTank** - Community-verified phishing labels
- **Tranco** - Research-oriented ranking list