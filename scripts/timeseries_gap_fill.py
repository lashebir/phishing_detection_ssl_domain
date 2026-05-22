#!/usr/bin/env python3
"""
Time Series Gap Filling Utility

Fills gaps in time series aggregations by:
1. Creating a full time range at the desired frequency
2. Reindexing data to include missing time windows
3. Flagging gap windows rather than interpolating (preserves data integrity)

This is critical for time series analysis where missing data should be
explicitly marked rather than hidden through interpolation.

Usage:
    # As a script
    python scripts/timeseries_gap_fill.py features.parquet --freq 1H --output features_filled.parquet

    # As a module
    from scripts.timeseries_gap_fill import fill_time_gaps
    df_filled = fill_time_gaps(df, time_col='timestamp', freq='1H')

Example:
    Original data (with gap):
      2025-05-20 10:00:00  →  100 certs
      2025-05-20 11:00:00  →  MISSING
      2025-05-20 12:00:00  →  95 certs

    After gap-filling:
      2025-05-20 10:00:00  →  100 certs  (is_gap=False)
      2025-05-20 11:00:00  →  0 certs    (is_gap=True)
      2025-05-20 12:00:00  →  95 certs   (is_gap=False)
"""

import argparse
import sys
from pathlib import Path
from typing import Optional, List

import pandas as pd


def fill_time_gaps(
    df: pd.DataFrame,
    time_col: str = "timestamp",
    freq: str = "1H",
    fill_value: float = 0.0,
    count_cols: Optional[List[str]] = None
) -> pd.DataFrame:
    """
    Fill gaps in time series data with explicit gap markers.

    Args:
        df: DataFrame with time series data
        time_col: Name of timestamp column
        freq: Pandas frequency string (e.g., "1H", "5T", "1D")
        fill_value: Value to use for missing data (default: 0)
        count_cols: Columns to treat as counts (will be filled with fill_value).
                   If None, auto-detects numeric columns ending in "_count"

    Returns:
        DataFrame with gaps filled and is_gap column added
    """

    if time_col not in df.columns:
        raise ValueError(f"Time column '{time_col}' not found in DataFrame")

    # Ensure timestamp is datetime
    df = df.copy()
    df[time_col] = pd.to_datetime(df[time_col])

    # Auto-detect count columns if not specified
    if count_cols is None:
        count_cols = [
            col for col in df.columns
            if col.endswith("_count") or col == "count"
        ]

    # Create full date range
    full_range = pd.date_range(
        start=df[time_col].min(),
        end=df[time_col].max(),
        freq=freq,
        tz=df[time_col].dt.tz
    )

    # Reindex to full range
    df_filled = df.set_index(time_col).reindex(full_range)

    # Reset index and rename
    df_filled = df_filled.reset_index()
    df_filled = df_filled.rename(columns={"index": time_col})

    # Flag gap rows (rows with NaN in any count column)
    if count_cols:
        df_filled["is_gap"] = df_filled[count_cols].isna().any(axis=1)

        # Fill gaps in count columns with fill_value
        for col in count_cols:
            if col in df_filled.columns:
                df_filled[col] = df_filled[col].fillna(fill_value)
    else:
        # If no count columns, just check for any NaN
        df_filled["is_gap"] = df_filled.isna().any(axis=1)

    return df_filled


def aggregate_with_gap_fill(
    df: pd.DataFrame,
    time_col: str = "timestamp",
    freq: str = "1H",
    agg_funcs: Optional[dict] = None,
    count_cols: Optional[List[str]] = None
) -> pd.DataFrame:
    """
    Aggregate time series data and fill gaps.

    This is useful when you want to aggregate raw data (e.g., individual certs)
    into time windows (e.g., hourly) and ensure all windows are present.

    Args:
        df: DataFrame with raw time series data
        time_col: Name of timestamp column
        freq: Aggregation frequency (e.g., "1H", "5T")
        agg_funcs: Dict of {column: aggregation_function}
                   Default: {"*": "count"} (count all records)
        count_cols: Columns that represent counts (for gap filling)

    Returns:
        Aggregated DataFrame with gaps filled and is_gap column

    Example:
        # Aggregate individual certs into hourly windows
        aggs = aggregate_with_gap_fill(
            df_certs,
            time_col="timestamp",
            freq="1H",
            agg_funcs={
                "cert_index": "count",
                "entropy": "mean",
                "is_phishing": "sum"
            }
        )
    """

    if time_col not in df.columns:
        raise ValueError(f"Time column '{time_col}' not found in DataFrame")

    # Ensure timestamp is datetime
    df = df.copy()
    df[time_col] = pd.to_datetime(df[time_col])

    # Set index for resampling
    df_indexed = df.set_index(time_col)

    # Default aggregation: count records
    if agg_funcs is None:
        agg_funcs = {"cert_index": "count" if "cert_index" in df.columns else "size"}

    # Resample and aggregate
    aggs = df_indexed.resample(freq).agg(agg_funcs)

    # Reset index (resampling creates DatetimeIndex)
    aggs = aggs.reset_index()

    # Rename columns if needed
    if "cert_index" in aggs.columns and agg_funcs.get("cert_index") == "count":
        aggs = aggs.rename(columns={"cert_index": "cert_count"})

    # Auto-detect count columns
    if count_cols is None:
        count_cols = [col for col in aggs.columns if "count" in col.lower()]

    # Fill gaps
    aggs_filled = fill_time_gaps(
        aggs,
        time_col=time_col,
        freq=freq,
        count_cols=count_cols
    )

    return aggs_filled


def main():
    parser = argparse.ArgumentParser(
        description="Fill gaps in time series data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument("input", help="Input parquet or CSV file")
    parser.add_argument("-o", "--output", help="Output file (default: add _filled suffix)")
    parser.add_argument("--time-col", default="timestamp",
                        help="Name of timestamp column (default: timestamp)")
    parser.add_argument("--freq", default="1H",
                        help="Time frequency for gap filling (default: 1H)")
    parser.add_argument("--aggregate", action="store_true",
                        help="Aggregate data to specified frequency before gap filling")
    parser.add_argument("--count-cols", nargs="+",
                        help="Columns to treat as counts (will be filled with 0)")

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    # Read input
    print(f"Loading data from {args.input} ...")
    if input_path.suffix == ".parquet":
        df = pd.read_parquet(input_path)
    elif input_path.suffix == ".csv":
        df = pd.read_csv(input_path)
    else:
        print(f"Error: Unsupported file type: {input_path.suffix}", file=sys.stderr)
        print("Supported: .parquet, .csv", file=sys.stderr)
        sys.exit(1)

    print(f"  Loaded {len(df):,} rows")

    # Process
    if args.aggregate:
        print(f"Aggregating to {args.freq} windows with gap filling ...")
        df_out = aggregate_with_gap_fill(
            df,
            time_col=args.time_col,
            freq=args.freq,
            count_cols=args.count_cols
        )
    else:
        print(f"Filling gaps at {args.freq} frequency ...")
        df_out = fill_time_gaps(
            df,
            time_col=args.time_col,
            freq=args.freq,
            count_cols=args.count_cols
        )

    # Output path
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.with_stem(input_path.stem + "_filled")

    # Write output
    print(f"Writing to {output_path} ...")
    if output_path.suffix == ".parquet":
        df_out.to_parquet(output_path, index=False)
    elif output_path.suffix == ".csv":
        df_out.to_csv(output_path, index=False)
    else:
        print(f"Error: Unsupported output type: {output_path.suffix}", file=sys.stderr)
        sys.exit(1)

    # Summary
    gap_count = df_out["is_gap"].sum()
    gap_pct = gap_count / len(df_out) * 100 if len(df_out) > 0 else 0

    print()
    print("Summary:")
    print(f"  Input rows:     {len(df):,}")
    print(f"  Output rows:    {len(df_out):,}")
    print(f"  Gap rows:       {gap_count:,} ({gap_pct:.1f}%)")
    print(f"  Complete rows:  {len(df_out) - gap_count:,} ({100 - gap_pct:.1f}%)")
    print()
    print(f"✅ Saved to {output_path}")


if __name__ == "__main__":
    main()
