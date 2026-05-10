"""
Phishing Detection Dashboard
=============================
Streamlit dashboard for model results, data export, and drift detection.

Install:
    pip install streamlit plotly scipy

Run:
    streamlit run dashboard.py
"""

import io
import json
import warnings
from datetime import datetime, timezone, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import streamlit as st
from scipy import stats

warnings.filterwarnings("ignore")

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="SSL Phishing Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Theme ─────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'IBM Plex Sans', sans-serif;
    }
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
    .stAlert { border-radius: 2px; }
    [data-testid="stSidebar"] {
        background: #0a0a0a;
        border-right: 1px solid #1a1a1a;
    }
</style>
""", unsafe_allow_html=True)

# ── Constants ─────────────────────────────────────────────────────────────────

PHISHING_COLOR  = "#ff4444"
LEGIT_COLOR     = "#44aaff"
NEUTRAL_COLOR   = "#888888"
WARN_COLOR      = "#ffaa00"

DEFAULT_CERTS_FILE   = "certs_fallback.jsonl"
DEFAULT_LABELS_FILE  = "phishtank_labels.jsonl"
DEFAULT_FEATURES_FILE = "features.parquet"

# ── Data loading ──────────────────────────────────────────────────────────────

@st.cache_data(ttl=300)
def load_features(path: str) -> pd.DataFrame:
    p = Path(path)
    if not p.exists():
        return pd.DataFrame()
    if p.suffix == ".parquet":
        return pd.read_parquet(path)
    return pd.read_json(path, lines=True)


@st.cache_data(ttl=300)
def load_jsonl(path: str) -> pd.DataFrame:
    if not Path(path).exists():
        return pd.DataFrame()
    return pd.read_json(path, lines=True)


@st.cache_data(ttl=60)
def load_live_stream(path: str, max_rows: int = 100_000) -> pd.DataFrame:
    """Load live streaming data, most recent rows first."""
    if not Path(path).exists():
        return pd.DataFrame()
    df = pd.read_json(path, lines=True)
    return df.tail(max_rows)


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ SSL Phishing Detection")
    st.markdown("---")

    page = st.radio(
        "Navigation",
        ["Model Results", "Data Explorer", "Drift Detection"],
        label_visibility="collapsed",
    )

    st.markdown("---")
    st.markdown("**Data Sources**")

    features_path = st.text_input("Features file", DEFAULT_FEATURES_FILE)
    certs_path    = st.text_input("Live certs", DEFAULT_CERTS_FILE)
    labels_path   = st.text_input("Labels file", DEFAULT_LABELS_FILE)

    st.markdown("---")

    # File status indicators
    for label, path in [("Features", features_path), ("Certs", certs_path), ("Labels", labels_path)]:
        exists = Path(path).exists()
        icon = "🟢" if exists else "🔴"
        st.markdown(f"{icon} `{label}`")

    st.markdown("---")
    if st.button("🔄 Refresh Data"):
        st.cache_data.clear()
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# PAGE 1: MODEL RESULTS
# ══════════════════════════════════════════════════════════════════════════════

if page == "Model Results":
    st.title("Model Results")

    df = load_features(features_path)

    if df.empty:
        st.warning(f"No features file found at `{features_path}`. Run `feature_engineering.py` first.")
        st.stop()

    # ── Summary metrics ───────────────────────────────────────────────────────

    total      = len(df)
    phishing   = int(df["y"].sum()) if "y" in df.columns else 0
    legit      = total - phishing
    phish_rate = phishing / total if total else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Domains",    f"{total:,}")
    c2.metric("Phishing (y=1)",   f"{phishing:,}")
    c3.metric("Legitimate (y=0)", f"{legit:,}")
    c4.metric("Phishing Rate",    f"{phish_rate:.3%}")

    st.markdown("---")

    # ── Feature distributions ─────────────────────────────────────────────────

    st.subheader("Feature Distributions by Class")

    feature_cols = [c for c in ["entropy", "tld_risk", "domain_length", "subdomain_count",
                                 "brand_distance", "validity_days", "san_count"]
                    if c in df.columns]

    if feature_cols and "y" in df.columns:
        selected_feature = st.selectbox("Select feature", feature_cols)

        fig = go.Figure()
        for label, color, name in [(0, LEGIT_COLOR, "Legitimate"), (1, PHISHING_COLOR, "Phishing")]:
            subset = df[df["y"] == label][selected_feature].dropna()
            fig.add_trace(go.Histogram(
                x=subset, name=name,
                marker_color=color, opacity=0.7,
                nbinsx=50,
            ))
        fig.update_layout(
            barmode="overlay",
            template="plotly_dark",
            paper_bgcolor="#0a0a0a",
            plot_bgcolor="#0f0f0f",
            font=dict(family="IBM Plex Mono", size=11),
            legend=dict(orientation="h", y=1.1),
            margin=dict(t=30, b=30, l=40, r=20),
            height=350,
        )
        st.plotly_chart(fig, use_container_width=True)

    # ── Feature importance (if model scores available) ────────────────────────

    st.subheader("Feature Means by Class")

    if "y" in df.columns and feature_cols:
        means = df.groupby("y")[feature_cols].mean().T
        means.columns = ["Legitimate", "Phishing"]
        means["Ratio (Phish/Legit)"] = (means["Phishing"] / means["Legitimate"].replace(0, np.nan)).round(2)
        means = means.sort_values("Ratio (Phish/Legit)", ascending=False)

        st.dataframe(
            means.style
                .background_gradient(subset=["Ratio (Phish/Legit)"], cmap="RdYlGn_r")
                .format({"Legitimate": "{:.3f}", "Phishing": "{:.3f}", "Ratio (Phish/Legit)": "{:.2f}x"}),
            use_container_width=True,
        )

    # ── PR curve inputs ───────────────────────────────────────────────────────

    st.subheader("Operating Threshold")
    st.info(
        "If you have model probability scores, add a `y_proba` column to your features "
        "file and the PR curve will render here. Currently showing class distribution only."
    )

    if "y_proba" in df.columns and "y" in df.columns:
        from sklearn.metrics import precision_recall_curve, average_precision_score

        precision, recall, thresholds = precision_recall_curve(df["y"], df["y_proba"])
        ap = average_precision_score(df["y"], df["y_proba"])

        min_precision = st.slider("Minimum acceptable precision", 0.1, 0.9, 0.3, 0.05)

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=recall, y=precision,
            mode="lines", name=f"Model (AP={ap:.3f})",
            line=dict(color=PHISHING_COLOR, width=2),
        ))
        fig.add_hline(y=min_precision, line_dash="dash",
                      line_color=WARN_COLOR,
                      annotation_text=f"Min precision = {min_precision}",
                      annotation_font_color=WARN_COLOR)
        fig.add_hline(y=phish_rate, line_dash="dot",
                      line_color=NEUTRAL_COLOR,
                      annotation_text="Random baseline",
                      annotation_font_color=NEUTRAL_COLOR)
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0a0a0a",
            plot_bgcolor="#0f0f0f",
            font=dict(family="IBM Plex Mono", size=11),
            xaxis_title="Recall",
            yaxis_title="Precision",
            height=400,
            margin=dict(t=30, b=40, l=50, r=20),
        )
        st.plotly_chart(fig, use_container_width=True)

        # Find optimal threshold
        valid_mask = precision[:-1] >= min_precision
        if valid_mask.any():
            best_idx  = recall[:-1][valid_mask].argmax()
            best_t    = thresholds[valid_mask][best_idx]
            best_r    = recall[:-1][valid_mask][best_idx]
            best_p    = precision[:-1][valid_mask][best_idx]
            st.success(f"Optimal threshold: **{best_t:.3f}** → Recall: **{best_r:.3f}** | Precision: **{best_p:.3f}**")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE 2: DATA EXPLORER + EXPORT
# ══════════════════════════════════════════════════════════════════════════════

elif page == "Data Explorer":
    st.title("Data Explorer")

    df = load_features(features_path)
    labels = load_jsonl(labels_path)

    if df.empty:
        st.warning(f"No features file found at `{features_path}`.")
        st.stop()

    # ── Filters ───────────────────────────────────────────────────────────────

    st.subheader("Filters")
    col1, col2, col3 = st.columns(3)

    with col1:
        label_filter = st.multiselect(
            "Label (y)", [0, 1],
            default=[0, 1],
            format_func=lambda x: "Phishing" if x == 1 else "Legitimate",
        )
    with col2:
        if "data_source" in df.columns:
            source_filter = st.multiselect(
                "Data source",
                df["data_source"].unique().tolist(),
                default=df["data_source"].unique().tolist(),
            )
        else:
            source_filter = None
    with col3:
        if "entropy" in df.columns:
            entropy_range = st.slider(
                "Entropy range",
                float(df["entropy"].min()),
                float(df["entropy"].max()),
                (float(df["entropy"].min()), float(df["entropy"].max())),
            )
        else:
            entropy_range = None

    # Apply filters
    mask = df["y"].isin(label_filter) if "y" in df.columns else pd.Series([True] * len(df))
    if source_filter and "data_source" in df.columns:
        mask &= df["data_source"].isin(source_filter)
    if entropy_range and "entropy" in df.columns:
        mask &= df["entropy"].between(*entropy_range)

    df_filtered = df[mask].reset_index(drop=True)

    st.markdown(f"**{len(df_filtered):,}** records match filters ({len(df_filtered)/len(df):.1%} of total)")

    # ── Table ─────────────────────────────────────────────────────────────────

    display_cols = [c for c in ["domain", "y", "entropy", "tld_risk", "data_source",
                                 "label_source", "brand_distance", "validity_days"]
                    if c in df_filtered.columns]

    st.dataframe(
        df_filtered[display_cols].head(1000),
        use_container_width=True,
        height=400,
    )

    if len(df_filtered) > 1000:
        st.caption(f"Showing first 1,000 of {len(df_filtered):,} rows. Export to see all.")

    # ── Export ────────────────────────────────────────────────────────────────

    st.subheader("Export")
    col1, col2, col3 = st.columns(3)

    with col1:
        csv_buffer = io.StringIO()
        df_filtered.to_csv(csv_buffer, index=False)
        st.download_button(
            "⬇️ Download CSV",
            data=csv_buffer.getvalue(),
            file_name=f"phishing_features_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with col2:
        jsonl_buffer = io.StringIO()
        for _, row in df_filtered.iterrows():
            jsonl_buffer.write(json.dumps(row.to_dict(), default=str) + "\n")
        st.download_button(
            "⬇️ Download JSONL",
            data=jsonl_buffer.getvalue(),
            file_name=f"phishing_features_{datetime.now().strftime('%Y%m%d_%H%M')}.jsonl",
            mime="application/jsonl",
            use_container_width=True,
        )

    with col3:
        parquet_buffer = io.BytesIO()
        df_filtered.to_parquet(parquet_buffer, index=False)
        st.download_button(
            "⬇️ Download Parquet",
            data=parquet_buffer.getvalue(),
            file_name=f"phishing_features_{datetime.now().strftime('%Y%m%d_%H%M')}.parquet",
            mime="application/octet-stream",
            use_container_width=True,
        )

    # ── Phishing domain list ───────────────────────────────────────────────────

    if "y" in df_filtered.columns and "domain" in df_filtered.columns:
        st.subheader("Flagged Domains")
        phishing_domains = df_filtered[df_filtered["y"] == 1]["domain"].dropna().unique()
        if len(phishing_domains):
            st.download_button(
                f"⬇️ Download Phishing Domain List ({len(phishing_domains):,} domains)",
                data="\n".join(phishing_domains),
                file_name=f"phishing_domains_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
                mime="text/plain",
                use_container_width=True,
            )


# ══════════════════════════════════════════════════════════════════════════════
# PAGE 3: DRIFT DETECTION
# ══════════════════════════════════════════════════════════════════════════════

elif page == "Drift Detection":
    st.title("Drift Detection")

    st.info(
        "Drift detection compares feature distributions between a reference window "
        "(your training data) and an incoming live stream. "
        "Wire in your live streaming file to activate real-time monitoring.",
        icon="ℹ️",
    )

    # ── Reference dataset ─────────────────────────────────────────────────────

    df_ref = load_features(features_path)
    df_live = load_live_stream(certs_path)

    if df_ref.empty:
        st.warning("No reference dataset found. Run feature engineering first.")
        st.stop()

    feature_cols = [c for c in ["entropy", "tld_risk", "domain_length",
                                 "subdomain_count", "brand_distance"]
                    if c in df_ref.columns]

    # ── Drift config ──────────────────────────────────────────────────────────

    st.subheader("Configuration")
    col1, col2 = st.columns(2)
    with col1:
        window_hours = st.slider("Live window (hours)", 1, 48, 24)
        pvalue_threshold = st.slider("KS test p-value threshold", 0.001, 0.1, 0.05, 0.001,
                                      help="Below this value = statistically significant drift")
    with col2:
        mean_shift_threshold = st.slider(
            "Mean shift alert threshold (%)", 5, 50, 20,
            help="Alert if feature mean shifts by more than this % from reference"
        )

    st.markdown("---")

    # ── Reference statistics ──────────────────────────────────────────────────

    st.subheader("Reference Distribution (Training Data)")

    ref_stats = df_ref[feature_cols].describe().T[["mean", "std", "50%"]].rename(
        columns={"50%": "median"}
    )
    st.dataframe(ref_stats.style.format("{:.4f}"), use_container_width=True)

    # ── Live drift analysis ───────────────────────────────────────────────────

    st.subheader("Live Stream Drift Analysis")

    if df_live.empty:
        st.warning(
            f"No live data found at `{certs_path}`. "
            "Start your streaming pipeline and point to the live certs file."
        )

        # Show what the drift panel will look like when data arrives
        st.markdown("**When live data is available, this panel will show:**")
        st.markdown("""
        - KS test statistic and p-value per feature
        - Mean shift % from reference
        - Alert flags for significant drift
        - Rolling feature distribution plots over time
        """)

    else:
        # Filter to window
        if "timestamp" in df_live.columns:
            df_live["timestamp"] = pd.to_datetime(df_live["timestamp"], utc=True)
            cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
            df_window = df_live[df_live["timestamp"] >= cutoff]
        else:
            df_window = df_live

        st.markdown(f"**{len(df_window):,}** records in last {window_hours}h window")

        # Compute features on live data if not already present
        live_feature_cols = [c for c in feature_cols if c in df_window.columns]

        if not live_feature_cols:
            st.warning(
                "Live certs file doesn't have engineered features yet. "
                "Run feature engineering on the live data first, or use the features.parquet output."
            )
        else:
            # ── KS drift tests ─────────────────────────────────────────────────

            drift_results = []
            for feature in live_feature_cols:
                ref_vals  = df_ref[feature].dropna().values
                live_vals = df_window[feature].dropna().values

                if len(live_vals) < 30:
                    continue

                ks_stat, p_value = stats.ks_2samp(ref_vals, live_vals)
                ref_mean  = ref_vals.mean()
                live_mean = live_vals.mean()
                mean_shift_pct = abs(live_mean - ref_mean) / (abs(ref_mean) + 1e-9) * 100

                drift_results.append({
                    "Feature":       feature,
                    "Ref Mean":      ref_mean,
                    "Live Mean":     live_mean,
                    "Mean Shift %":  mean_shift_pct,
                    "KS Statistic":  ks_stat,
                    "p-value":       p_value,
                    "Drift":         p_value < pvalue_threshold or mean_shift_pct > mean_shift_threshold,
                })

            df_drift = pd.DataFrame(drift_results)

            if df_drift.empty:
                st.info("Not enough live data to compute drift statistics yet.")
            else:
                # Summary alerts
                drifted = df_drift[df_drift["Drift"]]
                if len(drifted):
                    st.error(f"⚠️ Drift detected in {len(drifted)} feature(s): {', '.join(drifted['Feature'].tolist())}")
                else:
                    st.success("✅ No significant drift detected in current window")

                # Drift table
                def style_drift(val):
                    return "background-color: #3d1a1a; color: #ff4444;" if val else ""

                st.dataframe(
                    df_drift.style
                        .applymap(style_drift, subset=["Drift"])
                        .format({
                            "Ref Mean": "{:.4f}", "Live Mean": "{:.4f}",
                            "Mean Shift %": "{:.1f}%", "KS Statistic": "{:.4f}",
                            "p-value": "{:.4f}",
                        }),
                    use_container_width=True,
                )

                # ── Distribution overlay plots ─────────────────────────────────

                st.subheader("Distribution Overlays: Reference vs Live")

                for feature in live_feature_cols:
                    fig = go.Figure()
                    fig.add_trace(go.Histogram(
                        x=df_ref[feature].dropna(),
                        name="Reference", opacity=0.6,
                        marker_color=LEGIT_COLOR, nbinsx=40,
                        histnorm="probability density",
                    ))
                    fig.add_trace(go.Histogram(
                        x=df_window[feature].dropna(),
                        name="Live", opacity=0.6,
                        marker_color=WARN_COLOR, nbinsx=40,
                        histnorm="probability density",
                    ))

                    row = df_drift[df_drift["Feature"] == feature].iloc[0]
                    drift_flag = "⚠️ DRIFT" if row["Drift"] else "✅ OK"

                    fig.update_layout(
                        barmode="overlay",
                        title=f"{feature} — {drift_flag} (KS={row['KS Statistic']:.3f}, p={row['p-value']:.4f})",
                        template="plotly_dark",
                        paper_bgcolor="#0a0a0a",
                        plot_bgcolor="#0f0f0f",
                        font=dict(family="IBM Plex Mono", size=11),
                        height=280,
                        margin=dict(t=40, b=30, l=40, r=20),
                        legend=dict(orientation="h", y=1.15),
                    )
                    st.plotly_chart(fig, use_container_width=True)

                # ── Rolling cert volume ────────────────────────────────────────

                if "timestamp" in df_window.columns and len(df_window) > 100:
                    st.subheader("Cert Issuance Volume Over Time")

                    df_window["hour"] = df_window["timestamp"].dt.floor("h")
                    hourly = df_window.groupby("hour").size().reset_index(name="count")

                    fig = go.Figure()
                    fig.add_trace(go.Scatter(
                        x=hourly["hour"], y=hourly["count"],
                        mode="lines+markers",
                        line=dict(color=LEGIT_COLOR, width=2),
                        marker=dict(size=4),
                        name="Certs/hour",
                    ))

                    # Add mean line
                    mean_vol = hourly["count"].mean()
                    fig.add_hline(
                        y=mean_vol, line_dash="dash",
                        line_color=NEUTRAL_COLOR,
                        annotation_text=f"Mean: {mean_vol:.0f}/hr",
                    )

                    # Spike detection — flag hours > 2 std above mean
                    std_vol = hourly["count"].std()
                    spikes = hourly[hourly["count"] > mean_vol + 2 * std_vol]
                    if len(spikes):
                        fig.add_trace(go.Scatter(
                            x=spikes["hour"], y=spikes["count"],
                            mode="markers", name="Volume spike",
                            marker=dict(color=PHISHING_COLOR, size=10, symbol="x"),
                        ))

                    fig.update_layout(
                        template="plotly_dark",
                        paper_bgcolor="#0a0a0a",
                        plot_bgcolor="#0f0f0f",
                        font=dict(family="IBM Plex Mono", size=11),
                        xaxis_title="Time",
                        yaxis_title="Certs per hour",
                        height=350,
                        margin=dict(t=30, b=40, l=50, r=20),
                    )
                    st.plotly_chart(fig, use_container_width=True)

                    if len(spikes):
                        st.warning(
                            f"⚠️ {len(spikes)} volume spike(s) detected in current window. "
                            "Investigate these time periods for coordinated campaign activity."
                        )

    # ── Drift monitoring guide ─────────────────────────────────────────────────

    with st.expander("How drift detection works"):
        st.markdown("""
        **Kolmogorov-Smirnov (KS) Test**
        Compares the full distribution of each feature between reference and live data.
        A low p-value means the distributions are statistically different — not just that the means shifted.

        **Mean Shift %**
        Simple percentage change in feature mean. Catches gradual drift that KS may miss
        if the distribution shape is preserved but the center moves.

        **Volume Spike Detection**
        Flags hours where cert issuance is more than 2 standard deviations above the mean.
        Coordinated phishing campaigns typically show as sudden volume spikes, often clustering
        multiple lookalike domains in a short window.

        **What to do when drift is detected**
        1. Check which features drifted — entropy and tld_risk drifting together suggests a new campaign TLD preference
        2. Pull the domains from the drift window and score them with your current model
        3. If false negative rate has increased, retrain on a rolling window that includes recent data
        4. Track which brands are newly targeted via brand_distance on the drifted window
        """)
