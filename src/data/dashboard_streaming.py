"""
Streaming-Only Dashboard
========================
Dashboard for PURE streaming data from stream_48_hours_bg.sh
No historical data mixing - ready for production streaming pipeline.

This dashboard:
- Uses ONLY streaming data (argon_live source)
- Trains/evaluates on streaming labels (phishtank + tranco collected in real-time)
- Shows real-time metrics as streaming data accumulates
- Ready for continuous operation once phishing labels start flowing

Usage:
    streamlit run src/data/dashboard_streaming.py
"""

import io
import json
import warnings
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from scipy import stats

warnings.filterwarnings("ignore")

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="SSL Phishing - Streaming",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Theme ─────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

    html, body, [class*="css"] { font-family: 'IBM Plex Sans', sans-serif; }
    .stMetric label {
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #888;
    }
    .stMetric [data-testid="metric-container"] {
        background: #0f0f0f;
        border: 1px solid #222;
        border-radius: 4px;
        padding: 1rem;
    }
    .block-container { padding-top: 2rem; }
    h1, h2, h3 { font-family: 'IBM Plex Mono', monospace; }
    [data-testid="stSidebar"] {
        background: #0a0a0a;
        border-right: 1px solid #1a1a1a;
    }
    .streaming-badge {
        display: inline-block;
        background: #00ff88;
        color: black;
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.7rem;
        font-weight: 600;
        padding: 3px 8px;
        border-radius: 3px;
        letter-spacing: 0.05em;
        margin-left: 8px;
    }
</style>
""", unsafe_allow_html=True)

# ── Constants ─────────────────────────────────────────────────────────────────

PHISHING_COLOR = "#ff4444"
LEGIT_COLOR    = "#44aaff"
NEUTRAL_COLOR  = "#888888"
WARN_COLOR     = "#ffaa00"

DEFAULT_FEATURES_FILE = "features_streaming.parquet"
DEFAULT_MODEL_FILE    = "src/models/xgb_streaming.pkl"

# ── Data loading ──────────────────────────────────────────────────────────────

@st.cache_data(ttl=300)
def load_streaming_features(path: str, streaming_only: bool = True) -> pd.DataFrame:
    """Load features, optionally filtering to streaming data only"""
    p = Path(path)
    if not p.exists():
        # Fall back to regular features.parquet and filter
        p = Path("features.parquet")
        if not p.exists():
            return pd.DataFrame()

    df = pd.read_parquet(p)

    if streaming_only and 'data_source' in df.columns:
        # Filter to ONLY streaming data (exclude historical)
        df = df[df['data_source'] == 'argon_live'].copy()

    return df


@st.cache_resource
def load_model(path: str):
    """Load trained model"""
    import joblib
    if not Path(path).exists():
        # Fall back to demo model
        path = "src/models/xgb_model_0510.pkl"
        if not Path(path).exists():
            return None
    return joblib.load(path)


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 📡 Streaming Dashboard")
    st.markdown("**Pure streaming data - No historical mixing**")
    st.markdown("---")

    page = st.radio(
        "Navigation",
        ["Streaming Stats", "Model Performance", "Data Quality"],
        label_visibility="collapsed",
    )

    st.markdown("---")
    st.markdown("**Data Sources**")

    features_path = st.text_input("Features file", DEFAULT_FEATURES_FILE)
    model_path = st.text_input("Model file", DEFAULT_MODEL_FILE)

    st.markdown("---")

    # Data status
    streaming_certs = Path("sources/raw/certs_streaming_48h.jsonl")
    streaming_labels = Path("sources/raw/labels_streaming_48h.jsonl")

    st.markdown("**Streaming Pipeline Status:**")

    if streaming_certs.exists():
        cert_count = sum(1 for _ in open(streaming_certs))
        mtime = datetime.fromtimestamp(streaming_certs.stat().st_mtime)
        age = datetime.now() - mtime

        if age < timedelta(minutes=5):
            status = "🟢 LIVE"
        elif age < timedelta(hours=1):
            status = "🟡 RECENT"
        else:
            status = "⚪ STALE"

        st.markdown(f"{status} Certs: {cert_count:,}")
        st.markdown(f"<small>Updated: {age.seconds // 60}m ago</small>", unsafe_allow_html=True)
    else:
        st.markdown("🔴 No streaming data")

    if streaming_labels.exists():
        label_count = sum(1 for _ in open(streaming_labels))
        st.markdown(f"Labels: {label_count:,}")

    st.markdown("---")

    if st.button("🔄 Refresh Data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.markdown("---")

    with st.expander("ℹ️ About", expanded=False):
        st.markdown("""
        **Streaming Dashboard**

        This dashboard uses ONLY streaming data from `stream_48_hours_bg.sh`.

        No historical phishing data is mixed in, making this suitable for:
        - Production deployment
        - Real-time monitoring
        - Temporal consistency

        **Data flow:**
        1. `stream_48_hours_bg.sh` → certs + labels
        2. `pipeline_streaming.sh` → features
        3. Model training on streaming-only data
        4. This dashboard

        **Note:** Phishing in real-time CT logs is rare (~0.01%).
        Wait for sufficient labels before training.
        """)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE 1: STREAMING STATS
# ══════════════════════════════════════════════════════════════════════════════

if page == "Streaming Stats":
    st.markdown("# Streaming Stats <span class='streaming-badge'>STREAMING</span>",
                unsafe_allow_html=True)

    df = load_streaming_features(features_path, streaming_only=True)

    if df.empty:
        st.warning(f"""
        No streaming data found at `{features_path}`.

        **To generate streaming-only features:**
        ```bash
        # Use pipeline_streaming.sh which already filters to streaming data
        ./scripts/pipeline_streaming.sh
        ```

        Or filter manually:
        ```python
        import pandas as pd
        df = pd.read_parquet('features.parquet')
        df_streaming = df[df['data_source'] == 'argon_live']
        df_streaming.to_parquet('features_streaming.parquet')
        ```
        """)
        st.stop()

    total = len(df)

    # Label stats
    if 'label_source' in df.columns:
        phishtank_count = (df['label_source'] == 'phishtank').sum()
        tranco_count = (df['label_source'] == 'tranco').sum()
        unknown_count = (df['label_source'] == 'unknown').sum()
    else:
        phishtank_count = tranco_count = unknown_count = 0

    labeled_count = phishtank_count + tranco_count

    # Metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Streaming", f"{total:,}")
    col2.metric("🔴 Phishing", f"{phishtank_count:,}")
    col3.metric("🟢 Legitimate", f"{tranco_count:,}")
    col4.metric("⚪ Unlabeled", f"{unknown_count:,}")
    col5.metric("Label Rate", f"{labeled_count/total*100:.3f}%" if total > 0 else "0%")

    st.markdown("---")

    # Warning if insufficient labels
    if labeled_count < 1000:
        st.warning(f"""
        ⚠️ **Insufficient labels for training** ({labeled_count:,} labeled)

        **Why so few?**
        - Phishing in real-time CT logs is rare (~0.01% of domains)
        - PhishTank updates hourly with ~50-200 new domains
        - Tranco top-10K provides legitimate labels

        **Recommendations:**
        1. **Wait longer** - Let streaming collect for 7+ days to accumulate labels
        2. **Check PhishTank API** - Verify `PHISHTANK_API_KEY` is set
        3. **Monitor collection** - `tail -f stream.log`

        **Current rate:** {labeled_count} labels in {total:,} certs = {labeled_count/total*100:.4f}%

        **Estimated time to 10K labels:** {int((10000 - labeled_count) / (labeled_count / max(total, 1)) * total / 50 / 60)} hours
        (at current streaming rate of ~50 certs/min)
        """)

    # Label distribution over time
    if 'timestamp' in df.columns and labeled_count > 0:
        st.subheader("Label Collection Over Time")

        df_labeled = df[df['label_source'].isin(['phishtank', 'tranco'])].copy()
        df_labeled['timestamp'] = pd.to_datetime(df_labeled['timestamp'])
        df_labeled = df_labeled.sort_values('timestamp')

        # Cumulative counts
        df_labeled['phishing_cumsum'] = (df_labeled['label_source'] == 'phishtank').cumsum()
        df_labeled['legit_cumsum'] = (df_labeled['label_source'] == 'tranco').cumsum()

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df_labeled['timestamp'],
            y=df_labeled['phishing_cumsum'],
            name='Phishing (cumulative)',
            line=dict(color=PHISHING_COLOR, width=2)
        ))
        fig.add_trace(go.Scatter(
            x=df_labeled['timestamp'],
            y=df_labeled['legit_cumsum'],
            name='Legitimate (cumulative)',
            line=dict(color=LEGIT_COLOR, width=2)
        ))

        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0a0a0a",
            plot_bgcolor="#0f0f0f",
            font=dict(family="IBM Plex Mono", size=11),
            xaxis_title="Time",
            yaxis_title="Cumulative Count",
            height=400,
            margin=dict(t=30, b=40, l=50, r=20)
        )

        st.plotly_chart(fig, use_container_width=True)

    # Feature statistics
    st.subheader("Streaming Feature Distribution")

    if 'entropy' in df.columns and 'tld_risk' in df.columns:
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**Entropy**")
            st.metric("Mean", f"{df['entropy'].mean():.3f}")
            st.metric("Median", f"{df['entropy'].median():.3f}")

        with col2:
            st.markdown("**TLD Risk**")
            risk_dist = df['tld_risk'].value_counts().to_dict()
            for risk, count in sorted(risk_dist.items()):
                risk_name = {0: "Trust", 1: "Neutral", 2: "High-Risk"}.get(risk, "Unknown")
                st.metric(risk_name, f"{count:,}")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE 2: MODEL PERFORMANCE
# ══════════════════════════════════════════════════════════════════════════════

elif page == "Model Performance":
    st.markdown("# Model Performance <span class='streaming-badge'>STREAMING</span>",
                unsafe_allow_html=True)

    df = load_streaming_features(features_path, streaming_only=True)
    model = load_model(model_path)

    if df.empty:
        st.warning("No streaming data found. Generate features first.")
        st.stop()

    # Filter to labeled data
    df_labeled = df[df['label_source'].isin(['phishtank', 'tranco'])].copy()

    if len(df_labeled) == 0:
        st.warning("""
        No labeled streaming data yet.

        Wait for PhishTank/Tranco labels to accumulate from the streaming pipeline.

        Check streaming status in the sidebar.
        """)
        st.stop()

    st.success(f"✅ Found {len(df_labeled):,} labeled streaming records")

    # Label distribution
    col1, col2, col3 = st.columns(3)
    phishing = (df_labeled['y'] == 1).sum()
    legitimate = (df_labeled['y'] == 0).sum()

    col1.metric("Phishing", f"{phishing:,}")
    col2.metric("Legitimate", f"{legitimate:,}")
    col3.metric("Class Ratio", f"{legitimate/phishing:.1f}:1" if phishing > 0 else "N/A")

    if phishing < 100:
        st.warning(f"""
        ⚠️ Only {phishing} phishing samples - insufficient for reliable evaluation.

        **Minimum recommended:** 1,000 phishing samples for stable metrics.

        Continue streaming collection to accumulate more labels.
        """)

    st.markdown("---")

    # Model evaluation
    if model and 'y_proba' in df_labeled.columns:
        st.subheader("Operating Threshold")

        from sklearn.metrics import precision_recall_curve, average_precision_score

        precision, recall, thresholds = precision_recall_curve(df_labeled['y'], df_labeled['y_proba'])
        ap = average_precision_score(df_labeled['y'], df_labeled['y_proba'])

        phish_rate = phishing / len(df_labeled) if len(df_labeled) > 0 else 0

        min_precision = st.slider("Minimum acceptable precision", 0.1, 0.9, 0.5, 0.05)

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=recall, y=precision,
            mode="lines",
            name=f"Model (AP={ap:.3f})",
            line=dict(color=PHISHING_COLOR, width=2)
        ))
        fig.add_hline(
            y=min_precision,
            line_dash="dash",
            line_color=WARN_COLOR,
            annotation_text=f"Min precision = {min_precision}",
            annotation_font_color=WARN_COLOR
        )
        fig.add_hline(
            y=phish_rate,
            line_dash="dot",
            line_color=NEUTRAL_COLOR,
            annotation_text="Random baseline",
            annotation_font_color=NEUTRAL_COLOR
        )

        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0a0a0a",
            plot_bgcolor="#0f0f0f",
            font=dict(family="IBM Plex Mono", size=11),
            xaxis_title="Recall",
            yaxis_title="Precision",
            height=400,
            margin=dict(t=30, b=40, l=50, r=20)
        )

        st.plotly_chart(fig, use_container_width=True)

        # Optimal threshold
        valid = precision[:-1] >= min_precision
        if valid.any():
            best_idx = recall[:-1][valid].argmax()
            st.success(
                f"Optimal threshold: **{thresholds[valid][best_idx]:.3f}** → "
                f"Recall: **{recall[:-1][valid][best_idx]:.3f}** | "
                f"Precision: **{precision[:-1][valid][best_idx]:.3f}**"
            )
        else:
            st.error(f"No threshold achieves precision >= {min_precision}")

    elif 'y_proba' not in df_labeled.columns:
        st.info("""
        No predictions found. Train a model first:

        ```bash
        # Train streaming-only model
        python scripts/train_xgboost.py \\
            --input features_streaming.parquet \\
            --output src/models/xgb_streaming.pkl

        # Add predictions
        python scripts/add_predictions_to_features.py \\
            --features features_streaming.parquet \\
            --model src/models/xgb_streaming.pkl
        ```
        """)

    else:
        st.info(f"Model not found at `{model_path}`. Train a streaming-only model first.")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE 3: DATA QUALITY
# ══════════════════════════════════════════════════════════════════════════════

elif page == "Data Quality":
    st.markdown("# Data Quality <span class='streaming-badge'>STREAMING</span>",
                unsafe_allow_html=True)

    df = load_streaming_features(features_path, streaming_only=True)

    if df.empty:
        st.warning("No streaming data found.")
        st.stop()

    st.subheader("Data Completeness")

    # Check for missing values
    missing = df.isnull().sum()
    missing_pct = (missing / len(df) * 100).round(2)

    missing_df = pd.DataFrame({
        'Feature': missing.index,
        'Missing': missing.values,
        'Percent': missing_pct.values
    })
    missing_df = missing_df[missing_df['Missing'] > 0].sort_values('Missing', ascending=False)

    if len(missing_df) > 0:
        st.warning(f"Found {len(missing_df)} features with missing values:")
        st.dataframe(missing_df, use_container_width=True)
    else:
        st.success("✅ No missing values in streaming data")

    st.markdown("---")

    # Temporal coverage
    if 'timestamp' in df.columns:
        st.subheader("Temporal Coverage")

        df['timestamp'] = pd.to_datetime(df['timestamp'])

        col1, col2, col3 = st.columns(3)
        col1.metric("Start", df['timestamp'].min().strftime("%Y-%m-%d %H:%M"))
        col2.metric("End", df['timestamp'].max().strftime("%Y-%m-%d %H:%M"))

        duration = (df['timestamp'].max() - df['timestamp'].min()).total_seconds() / 3600
        col3.metric("Duration", f"{duration:.1f} hours")

        # Cert rate over time
        st.markdown("**Certificate Collection Rate**")

        df_hourly = df.set_index('timestamp').resample('1H').size().reset_index(name='count')

        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=df_hourly['timestamp'],
            y=df_hourly['count'],
            marker_color=LEGIT_COLOR
        ))

        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0a0a0a",
            plot_bgcolor="#0f0f0f",
            font=dict(family="IBM Plex Mono", size=11),
            xaxis_title="Time",
            yaxis_title="Certs/Hour",
            height=300,
            margin=dict(t=30, b=40, l=50, r=20)
        )

        st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")

    # Export
    st.subheader("Export Streaming Data")

    if st.button("📥 Export to CSV"):
        csv = df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"streaming_features_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
