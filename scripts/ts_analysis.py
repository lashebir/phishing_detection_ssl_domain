"""
Time Series Analysis — CT Log Phishing Detection
==================================================
Decomposes temporal patterns in cert issuance data and detects
anomalous windows that may indicate phishing campaigns.

Tool choice: STL decomposition (statsmodels) + Isolation Forest
- STL (Seasonal-Trend decomposition using LOESS) is robust to outliers,
  handles missing windows, and separates daily/weekly seasonality cleanly.
  Better than classical decomposition for this use case because phishing
  spikes ARE outliers and classical decomposition would let them distort
  the trend estimate.
- Prophet is an alternative but is heavier and designed for forecasting.
  You don't need forecasting — you need anomaly detection on residuals.
- Isolation Forest on STL residuals catches windows that can't be explained
  by normal trend + seasonality, which is exactly what a campaign looks like.

Install:
    pip install statsmodels scikit-learn plotly pandas pyarrow

Run:
    jupyter notebook ts_analysis.ipynb
    or: python ts_analysis.py
"""

import json
import warnings
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from statsmodels.tsa.seasonal import STL

warnings.filterwarnings("ignore")

# ── Config ────────────────────────────────────────────────────────────────────

HISTORICAL_FILE = "data/timeseries/certs_historical.jsonl"
LABELS_FILE     = "data/timeseries/phishtank_labels_timeseries.jsonl"
WINDOW          = "1h"        # aggregation window — 1h balances resolution vs noise
                              # use "30min" if you have dense data, "4h" if sparse
MIN_CERTS_PER_WINDOW = 10     # drop windows with fewer certs — likely gaps not signal
CONTAMINATION        = 0.05   # expected anomaly rate for Isolation Forest (5%)

# ── Plotting theme ────────────────────────────────────────────────────────────

LAYOUT = dict(
    template="plotly_dark",
    paper_bgcolor="#0a0a0a",
    plot_bgcolor="#0f0f0f",
    font=dict(family="IBM Plex Mono", size=11),
    margin=dict(t=50, b=40, l=60, r=20),
)
PHISHING_COLOR = "#ff4444"
LEGIT_COLOR    = "#44aaff"
TREND_COLOR    = "#ffaa00"
ANOMALY_COLOR  = "#ff44aa"


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — LOAD AND PREPARE
# ══════════════════════════════════════════════════════════════════════════════

print("=" * 70)
print("SECTION 1: Load and Prepare")
print("=" * 70)

df_raw = pd.read_json(HISTORICAL_FILE, lines=True)
print(f"Raw records: {len(df_raw):,}")

# Explode domains
df = df_raw.explode("domains").rename(columns={"domains": "domain"})
df = df.dropna(subset=["domain"])
df["domain"] = df["domain"].str.lower().str.lstrip("*.")

# Parse timestamps
df["cert_ts"] = pd.to_datetime(df["not_before"], unit="s", utc=True)
df = df.sort_values("cert_ts").reset_index(drop=True)

print(f"Domain rows: {len(df):,}")
print(f"Date range:  {df['cert_ts'].min()} → {df['cert_ts'].max()}")
print(f"Unique domains: {df['domain'].nunique():,}")

# Join labels
if Path(LABELS_FILE).exists():
    labels = pd.read_json(LABELS_FILE, lines=True)
    df = df.merge(labels[["domain", "y", "label_source"]], on="domain", how="left")
    df["y"] = df["y"].fillna(0).astype(int)
    print(f"Phishing (y=1): {df['y'].sum():,} ({df['y'].mean():.4%})")
else:
    df["y"] = 0
    print("No labels file found — all y=0")

# ── Feature engineering ───────────────────────────────────────────────────────

import math
from collections import Counter

HIGH_RISK_TLDS = {"top","xyz","buzz","click","live","online","site",
                  "club","work","shop","icu","vip","fun","today"}

def domain_entropy(domain: str) -> float:
    s = domain.replace(".", "")
    if not s: return 0.0
    counts = Counter(s)
    total  = len(s)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())

def tld_risk(domain: str) -> int:
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    return 2 if tld in HIGH_RISK_TLDS else 1

def is_letsencrypt(row) -> int:
    if isinstance(row, dict):
        return int("Let's Encrypt" in (row.get("O") or ""))
    return 0

df["entropy"]       = df["domain"].apply(domain_entropy)
df["tld_risk"]      = df["domain"].apply(tld_risk)
df["is_letsencrypt"]= df["issuer"].apply(is_letsencrypt) if "issuer" in df.columns else 0
df["domain_length"] = df["domain"].str.len()
df["subdomain_count"] = df["domain"].apply(lambda d: max(0, len(d.split(".")) - 2))

print("\nFeature engineering complete")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — AGGREGATE INTO TIME WINDOWS
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("SECTION 2: Aggregate into Time Windows")
print("=" * 70)

df["window"] = df["cert_ts"].dt.floor(WINDOW)

aggs = df.groupby("window").agg(
    # volume
    cert_count          = ("domain",          "count"),
    unique_domains      = ("domain",          "nunique"),

    # domain features — means per window
    mean_entropy        = ("entropy",         "mean"),
    mean_domain_length  = ("domain_length",   "mean"),
    mean_subdomain_count= ("subdomain_count", "mean"),

    # proportion features
    prop_high_risk_tld  = ("tld_risk",        lambda x: (x == 2).mean()),
    prop_letsencrypt    = ("is_letsencrypt",  "mean"),

    # label counts (where available)
    phishing_count      = ("y",               "sum"),
    phishing_rate       = ("y",               "mean"),
).reset_index()

# ── Fill gaps with complete time index ───────────────────────────────────────
# Critical: missing windows must be marked, not interpolated.
# An Isolation Forest trained with gaps filled by interpolation would
# learn interpolated values as "normal" and miss real anomalies.

full_index = pd.date_range(
    start=aggs["window"].min(),
    end=aggs["window"].max(),
    freq=WINDOW, tz="UTC",
)
aggs = aggs.set_index("window").reindex(full_index).reset_index()
aggs.columns = ["window"] + list(aggs.columns[1:])

# Mark and fill gaps
aggs["is_gap"] = aggs["cert_count"].isna()
aggs["cert_count"] = aggs["cert_count"].fillna(0)
aggs[["mean_entropy", "mean_domain_length", "prop_high_risk_tld",
      "prop_letsencrypt", "mean_subdomain_count"]] = \
    aggs[["mean_entropy", "mean_domain_length", "prop_high_risk_tld",
          "prop_letsencrypt", "mean_subdomain_count"]].fillna(method="ffill")

# Drop sparse windows (likely gaps in CT polling)
aggs_clean = aggs[
    (aggs["cert_count"] >= MIN_CERTS_PER_WINDOW) &
    (~aggs["is_gap"])
].copy().reset_index(drop=True)

print(f"Total windows:  {len(aggs):,}")
print(f"Gap windows:    {aggs['is_gap'].sum():,}")
print(f"Sparse windows: {((aggs['cert_count'] < MIN_CERTS_PER_WINDOW) & ~aggs['is_gap']).sum():,}")
print(f"Clean windows:  {len(aggs_clean):,}")
print(f"\nWindow stats:")
print(aggs_clean[["cert_count", "mean_entropy", "prop_high_risk_tld",
                   "prop_letsencrypt"]].describe().round(3))


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — STL DECOMPOSITION
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("SECTION 3: STL Decomposition")
print("=" * 70)

# ── Why STL? ──────────────────────────────────────────────────────────────────
# CT log cert issuance has strong daily seasonality (business hours see more
# cert issuance than weekends/nights) and a rising trend (more HTTPS over time).
# STL separates:
#   trend     — long-term direction (rising cert volume)
#   seasonal  — repeating pattern (daily/weekly cycles)
#   residual  — what's left after removing trend + seasonal
# Phishing campaigns appear as spikes in the RESIDUAL, not the raw series,
# because the raw series is dominated by normal seasonal variation.

# STL requires a set seasonal period.
# For hourly data: period=24 captures daily seasonality.
# If you have 2+ weeks: also run period=24*7 for weekly seasonality.

PERIOD = 24  # hours in a day

def run_stl(series: pd.Series, series_name: str) -> pd.DataFrame:
    """Run STL decomposition on a time series. Returns components df."""
    # STL needs a continuous series with consistent frequency
    # Use clean windows only, interpolate any remaining gaps
    s = series.copy()
    s = s.interpolate(method="linear").fillna(method="bfill").fillna(method="ffill")

    if len(s) < PERIOD * 2:
        print(f"  {series_name}: not enough data for STL (need {PERIOD*2} points, have {len(s)})")
        return pd.DataFrame()

    stl    = STL(s, period=PERIOD, robust=True)
    result = stl.fit()

    return pd.DataFrame({
        "observed": result.observed,
        "trend":    result.trend,
        "seasonal": result.seasonal,
        "residual": result.resid,
    }, index=series.index)


# Decompose cert_count and key feature series
decomp_results = {}
for series_name in ["cert_count", "mean_entropy", "prop_high_risk_tld"]:
    print(f"Decomposing {series_name} …")
    series = aggs_clean.set_index("window")[series_name]
    result = run_stl(series, series_name)
    if not result.empty:
        decomp_results[series_name] = result
        print(f"  Trend range:    {result['trend'].min():.3f} → {result['trend'].max():.3f}")
        print(f"  Seasonal range: {result['seasonal'].min():.3f} → {result['seasonal'].max():.3f}")
        print(f"  Residual std:   {result['residual'].std():.3f}")


# ── Plot decomposition for cert_count ─────────────────────────────────────────

if "cert_count" in decomp_results:
    dc = decomp_results["cert_count"]
    idx = aggs_clean["window"]

    fig = make_subplots(
        rows=4, cols=1,
        subplot_titles=["Observed", "Trend", "Seasonal", "Residual"],
        shared_xaxes=True, vertical_spacing=0.06,
    )
    for row, col, color, name in [
        (1, "observed", LEGIT_COLOR,   "Observed"),
        (2, "trend",    TREND_COLOR,   "Trend"),
        (3, "seasonal", "#44ffaa",     "Seasonal"),
        (4, "residual", ANOMALY_COLOR, "Residual"),
    ]:
        fig.add_trace(go.Scatter(
            x=idx, y=dc[col], mode="lines", name=name,
            line=dict(color=color, width=1),
        ), row=row, col=1)

    fig.update_layout(
        **LAYOUT,
        height=700,
        title="STL Decomposition — Cert Issuance Volume",
        showlegend=False,
    )
    fig.show()
    print("\nDecomposition plot rendered")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — ANOMALY DETECTION ON RESIDUALS
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("SECTION 4: Anomaly Detection on Residuals")
print("=" * 70)

# ── Build residual feature matrix ─────────────────────────────────────────────
# Use residuals from all decomposed series as features for Isolation Forest.
# The residual is the part of the signal that can't be explained by
# normal trend + seasonality — anomalies in multiple residuals simultaneously
# is a stronger campaign signal than any single series.

residual_features = {}
for name, dc in decomp_results.items():
    residual_features[f"resid_{name}"] = dc["residual"].values

if not residual_features:
    print("No decomposition results — check data volume")
else:
    # Align all residuals to clean windows index
    min_len = min(len(v) for v in residual_features.values())
    X_resid = pd.DataFrame({k: v[:min_len] for k, v in residual_features.items()})
    windows_aligned = aggs_clean["window"].iloc[:min_len].reset_index(drop=True)

    # Also include raw aggregate features that weren't decomposed
    extra_features = ["mean_subdomain_count", "prop_letsencrypt"]
    for feat in extra_features:
        if feat in aggs_clean.columns:
            vals = aggs_clean[feat].iloc[:min_len].fillna(0).values
            X_resid[feat] = vals

    # Scale before Isolation Forest
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X_resid)

    # Isolation Forest
    iso = IsolationForest(
        contamination=CONTAMINATION,
        n_estimators=200,
        random_state=42,
    )
    scores   = iso.fit_predict(X_scaled)
    raw_scores = iso.score_samples(X_scaled)  # lower = more anomalous

    aggs_clean = aggs_clean.iloc[:min_len].copy().reset_index(drop=True)
    aggs_clean["anomaly_flag"]  = (scores == -1).astype(int)
    aggs_clean["anomaly_score"] = raw_scores   # lower = more anomalous

    anomalies = aggs_clean[aggs_clean["anomaly_flag"] == 1]
    print(f"Anomalous windows: {len(anomalies):,} / {len(aggs_clean):,} "
          f"({len(anomalies)/len(aggs_clean):.1%})")

    # ── Z-score fallback for cert_count spikes ────────────────────────────────
    # Simple but interpretable — flag windows > 2.5 std above mean
    mean_vol = aggs_clean["cert_count"].mean()
    std_vol  = aggs_clean["cert_count"].std()
    aggs_clean["volume_spike"] = (
        aggs_clean["cert_count"] > mean_vol + 2.5 * std_vol
    ).astype(int)

    print(f"Volume spikes (z>2.5): {aggs_clean['volume_spike'].sum():,}")

    # ── Plot anomalies on cert volume ─────────────────────────────────────────

    normal   = aggs_clean[aggs_clean["anomaly_flag"] == 0]
    flagged  = aggs_clean[aggs_clean["anomaly_flag"] == 1]
    phish_w  = aggs_clean[aggs_clean["phishing_count"] > 0] \
               if "phishing_count" in aggs_clean.columns else pd.DataFrame()

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=normal["window"], y=normal["cert_count"],
        mode="lines", name="Normal",
        line=dict(color=LEGIT_COLOR, width=1), opacity=0.7,
    ))
    fig.add_trace(go.Scatter(
        x=flagged["window"], y=flagged["cert_count"],
        mode="markers", name="Anomaly (Isolation Forest)",
        marker=dict(color=ANOMALY_COLOR, size=8, symbol="x"),
    ))
    if len(phish_w):
        fig.add_trace(go.Scatter(
            x=phish_w["window"], y=phish_w["cert_count"],
            mode="markers", name="Known Phishing Window",
            marker=dict(color=PHISHING_COLOR, size=10, symbol="diamond"),
        ))
    fig.add_hline(
        y=mean_vol + 2.5 * std_vol,
        line_dash="dash", line_color=TREND_COLOR,
        annotation_text="2.5σ volume threshold",
        annotation_font_color=TREND_COLOR,
    )
    fig.update_layout(
        **LAYOUT, height=450,
        title="Cert Issuance Volume — Anomaly Detection",
        xaxis_title="Time", yaxis_title="Certs per hour",
    )
    fig.show()

    # ── Anomaly score over time ────────────────────────────────────────────────

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=aggs_clean["window"],
        y=aggs_clean["anomaly_score"],
        mode="lines", name="Anomaly score",
        line=dict(color=TREND_COLOR, width=1),
    ))
    threshold_score = np.percentile(aggs_clean["anomaly_score"], CONTAMINATION * 100)
    fig.add_hline(
        y=threshold_score,
        line_dash="dash", line_color=ANOMALY_COLOR,
        annotation_text=f"Anomaly threshold ({CONTAMINATION:.0%} contamination)",
        annotation_font_color=ANOMALY_COLOR,
    )
    fig.update_layout(
        **LAYOUT, height=350,
        title="Isolation Forest Anomaly Score (lower = more anomalous)",
        xaxis_title="Time", yaxis_title="Score",
    )
    fig.show()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — INVESTIGATE ANOMALOUS WINDOWS
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("SECTION 5: Investigate Anomalous Windows")
print("=" * 70)

if "anomaly_flag" in aggs_clean.columns:
    print("\nTop anomalous windows by score (lower = more anomalous):")
    top_anomalies = (
        aggs_clean[aggs_clean["anomaly_flag"] == 1]
        .sort_values("anomaly_score")
        [["window", "cert_count", "mean_entropy", "prop_high_risk_tld",
          "prop_letsencrypt", "phishing_count", "anomaly_score"]]
        .head(20)
    )
    print(top_anomalies.to_string(index=False))

    # ── Drill into the most anomalous window ──────────────────────────────────

    if len(top_anomalies):
        worst_window = top_anomalies.iloc[0]["window"]
        print(f"\nDrilling into most anomalous window: {worst_window}")

        window_end   = worst_window + pd.Timedelta(WINDOW)
        window_certs = df[
            (df["cert_ts"] >= worst_window) &
            (df["cert_ts"] <  window_end)
        ].copy()

        print(f"Certs in window: {len(window_certs):,}")
        print(f"\nTop TLDs:")
        print(window_certs["domain"].apply(
            lambda d: d.rsplit(".", 1)[-1] if "." in d else d
        ).value_counts().head(10))

        print(f"\nHighest entropy domains:")
        print(
            window_certs.nlargest(10, "entropy")[["domain", "entropy", "y"]]
            .to_string(index=False)
        )

        if window_certs["y"].sum() > 0:
            print(f"\nPhishing domains in window:")
            print(window_certs[window_certs["y"] == 1][["domain", "entropy"]].to_string(index=False))

    # ── Feature radar for anomalous vs normal windows ─────────────────────────

    radar_features = ["mean_entropy", "prop_high_risk_tld", "prop_letsencrypt",
                      "mean_subdomain_count", "mean_domain_length"]
    radar_features = [f for f in radar_features if f in aggs_clean.columns]

    if radar_features:
        normal_means  = aggs_clean[aggs_clean["anomaly_flag"] == 0][radar_features].mean()
        anomaly_means = aggs_clean[aggs_clean["anomaly_flag"] == 1][radar_features].mean()

        # Normalise to 0-1 for radar
        combined = pd.concat([normal_means, anomaly_means], axis=1)
        combined.columns = ["Normal", "Anomalous"]
        combined_norm = (combined - combined.min()) / (combined.max() - combined.min() + 1e-9)

        fig = go.Figure()
        for col, color in [("Normal", LEGIT_COLOR), ("Anomalous", ANOMALY_COLOR)]:
            fig.add_trace(go.Scatterpolar(
                r=combined_norm[col].tolist() + [combined_norm[col].iloc[0]],
                theta=radar_features + [radar_features[0]],
                fill="toself", name=col,
                line=dict(color=color),
                opacity=0.7,
            ))
        fig.update_layout(
            **LAYOUT, height=450,
            title="Feature Profile: Normal vs Anomalous Windows",
            polar=dict(bgcolor="#0f0f0f"),
        )
        fig.show()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — WEEKLY SEASONALITY (if 2+ weeks of data)
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("SECTION 6: Weekly Seasonality")
print("=" * 70)

n_weeks = (aggs_clean["window"].max() - aggs_clean["window"].min()).days / 7
print(f"Data covers {n_weeks:.1f} weeks")

if n_weeks >= 2:
    aggs_clean["hour_of_day"]  = aggs_clean["window"].dt.hour
    aggs_clean["day_of_week"]  = aggs_clean["window"].dt.day_name()

    # ── Average cert volume by hour of day ────────────────────────────────────

    hourly_profile = aggs_clean.groupby("hour_of_day")["cert_count"].mean()

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=hourly_profile.index, y=hourly_profile.values,
        marker_color=LEGIT_COLOR, name="Avg certs",
    ))
    fig.update_layout(
        **LAYOUT, height=350,
        title="Average Cert Volume by Hour of Day (UTC)",
        xaxis_title="Hour (UTC)", yaxis_title="Avg certs/hour",
    )
    fig.show()

    # ── Average entropy by hour — does phishing peak at certain hours? ────────

    hourly_entropy = aggs_clean.groupby("hour_of_day")["mean_entropy"].mean()

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=hourly_entropy.index, y=hourly_entropy.values,
        mode="lines+markers", name="Mean entropy",
        line=dict(color=TREND_COLOR, width=2),
        marker=dict(size=6),
    ))
    fig.update_layout(
        **LAYOUT, height=300,
        title="Mean Domain Entropy by Hour of Day",
        xaxis_title="Hour (UTC)", yaxis_title="Mean entropy",
    )
    fig.show()

    # ── Day of week patterns ──────────────────────────────────────────────────

    day_order = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
    daily = aggs_clean.groupby("day_of_week").agg(
        mean_certs  = ("cert_count",         "mean"),
        mean_entropy= ("mean_entropy",        "mean"),
        mean_phish  = ("prop_high_risk_tld",  "mean"),
    ).reindex(day_order)

    fig = make_subplots(rows=1, cols=3,
                        subplot_titles=["Cert Volume", "Mean Entropy", "High-Risk TLD Rate"])
    for col_idx, (col, color) in enumerate(
        [("mean_certs", LEGIT_COLOR), ("mean_entropy", TREND_COLOR), ("mean_phish", PHISHING_COLOR)], 1
    ):
        fig.add_trace(go.Bar(
            x=daily.index, y=daily[col],
            marker_color=color, showlegend=False,
        ), row=1, col=col_idx)

    fig.update_layout(**LAYOUT, height=350, title="Day of Week Patterns")
    fig.show()

else:
    print("Less than 2 weeks of data — weekly seasonality analysis skipped.")
    print("Continue collecting and re-run once you have 14+ days.")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — SAVE OUTPUTS
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("SECTION 7: Save Outputs")
print("=" * 70)

Path("data/timeseries").mkdir(parents=True, exist_ok=True)

# Aggregated windows with anomaly flags
aggs_clean.to_parquet("data/timeseries/windows.parquet", index=False)
print(f"Saved: data/timeseries/windows.parquet ({len(aggs_clean):,} windows)")

# Anomalous windows only — for investigation
if "anomaly_flag" in aggs_clean.columns:
    anomalies = aggs_clean[aggs_clean["anomaly_flag"] == 1]
    anomalies.to_parquet("data/timeseries/anomalous_windows.parquet", index=False)
    print(f"Saved: data/timeseries/anomalous_windows.parquet ({len(anomalies):,} windows)")

# STL residuals
if decomp_results:
    resid_df = pd.DataFrame(
        {f"resid_{k}": v["residual"] for k, v in decomp_results.items()}
    )
    resid_df.to_parquet("data/timeseries/stl_residuals.parquet", index=False)
    print(f"Saved: data/timeseries/stl_residuals.parquet")

print("\n── Summary ──────────────────────────────────────────────────────────")
print(f"Windows analysed:  {len(aggs_clean):,}")
if "anomaly_flag" in aggs_clean.columns:
    print(f"Anomalies flagged: {aggs_clean['anomaly_flag'].sum():,} "
          f"({aggs_clean['anomaly_flag'].mean():.1%})")
if "phishing_count" in aggs_clean.columns:
    phish_windows = (aggs_clean["phishing_count"] > 0).sum()
    print(f"Windows with known phishing: {phish_windows:,}")
    if phish_windows:
        overlap = (
            (aggs_clean["anomaly_flag"] == 1) & (aggs_clean["phishing_count"] > 0)
        ).sum()
        print(f"Phishing windows also flagged as anomalous: {overlap:,} / {phish_windows:,}")
