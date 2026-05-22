#!/usr/bin/env python3
"""
Session Gap Marking Utility

Uses session logs (START/STOP events) to distinguish between:
1. Intentional gaps (streaming pipeline was not running)
2. Data collection issues (pipeline running but no data)

This helps identify:
- Expected downtime (manual stops, crashes, maintenance)
- Unexpected gaps (API issues, network problems, bugs)

Session log format:
    START,2025-05-20T10:00:00Z
    STOP,2025-05-20T12:00:00Z
    START,2025-05-20T14:00:00Z
    STOP,2025-05-20T16:00:00Z

Usage:
    python scripts/mark_session_gaps.py \\
        --data features.parquet \\
        --sessions sources/raw/stream_sessions.log \\
        --output features_with_gaps.parquet

    # Or as a module
    from scripts.mark_session_gaps import mark_session_gaps
    df = mark_session_gaps(df, session_log_path="stream_sessions.log")
"""

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

import pandas as pd


def load_session_log(log_path: str) -> pd.DataFrame:
    """
    Load session log and parse START/STOP events.

    Returns DataFrame with columns:
        - event: "START" or "STOP"
        - timestamp: datetime
    """
    sessions = []

    with open(log_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or ',' not in line:
                continue

            parts = line.split(',', 1)
            if len(parts) != 2:
                continue

            event, ts_str = parts
            event = event.strip().upper()

            if event not in ["START", "STOP"]:
                continue

            try:
                timestamp = pd.to_datetime(ts_str.strip())
                sessions.append({"event": event, "timestamp": timestamp})
            except Exception:
                continue

    return pd.DataFrame(sessions)


def get_active_ranges(sessions_df: pd.DataFrame) -> List[Tuple[pd.Timestamp, pd.Timestamp]]:
    """
    Extract active time ranges from session log.

    Returns list of (start, stop) tuples representing periods when
    the streaming pipeline was running.

    Handles:
    - Multiple START/STOP cycles
    - Unpaired events (START without STOP, STOP without START)
    - Out-of-order events
    """

    if sessions_df.empty:
        return []

    # Sort by timestamp
    sessions_df = sessions_df.sort_values("timestamp").reset_index(drop=True)

    ranges = []
    current_start = None

    for _, row in sessions_df.iterrows():
        if row["event"] == "START":
            if current_start is None:
                current_start = row["timestamp"]
            else:
                # Duplicate START — ignore (or close previous range)
                pass

        elif row["event"] == "STOP":
            if current_start is not None:
                ranges.append((current_start, row["timestamp"]))
                current_start = None
            else:
                # STOP without START — ignore
                pass

    # Handle unclosed START (pipeline still running)
    if current_start is not None:
        # Use current time as end
        ranges.append((current_start, pd.Timestamp.now(tz=timezone.utc)))

    return ranges


def is_within_active_range(timestamp: pd.Timestamp, active_ranges: List[Tuple[pd.Timestamp, pd.Timestamp]]) -> bool:
    """Check if timestamp falls within any active range."""
    for start, stop in active_ranges:
        if start <= timestamp <= stop:
            return True
    return False


def mark_session_gaps(
    df: pd.DataFrame,
    session_log_path: str,
    time_col: str = "timestamp",
    output_col: str = "is_session_gap"
) -> pd.DataFrame:
    """
    Mark rows that fall outside active streaming sessions.

    Args:
        df: DataFrame with time series data
        session_log_path: Path to session log file
        time_col: Name of timestamp column
        output_col: Name of output boolean column

    Returns:
        DataFrame with output_col added:
        - True if timestamp is outside any session range (intentional gap)
        - False if timestamp is within a session range

    This allows distinguishing:
    - is_gap=True, is_session_gap=True → expected (pipeline not running)
    - is_gap=True, is_session_gap=False → unexpected (pipeline running but no data)
    """

    if time_col not in df.columns:
        raise ValueError(f"Time column '{time_col}' not found in DataFrame")

    # Load session log
    if not Path(session_log_path).exists():
        print(f"Warning: Session log not found at {session_log_path}", file=sys.stderr)
        print(f"All gaps will be marked as unexpected", file=sys.stderr)
        df[output_col] = False
        return df

    sessions_df = load_session_log(session_log_path)

    if sessions_df.empty:
        print(f"Warning: No valid sessions found in {session_log_path}", file=sys.stderr)
        df[output_col] = False
        return df

    # Get active ranges
    active_ranges = get_active_ranges(sessions_df)

    print(f"Found {len(active_ranges)} active streaming sessions:")
    for i, (start, stop) in enumerate(active_ranges, 1):
        duration = stop - start
        print(f"  {i}. {start} → {stop} ({duration})")

    # Ensure time column is datetime
    df = df.copy()
    df[time_col] = pd.to_datetime(df[time_col])

    # Mark session gaps
    df[output_col] = ~df[time_col].apply(
        lambda ts: is_within_active_range(ts, active_ranges)
    )

    return df


def main():
    parser = argparse.ArgumentParser(
        description="Mark session gaps in time series data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument("-d", "--data", required=True,
                        help="Input data file (parquet or CSV)")
    parser.add_argument("-s", "--sessions", required=True,
                        help="Session log file")
    parser.add_argument("-o", "--output",
                        help="Output file (default: add _with_gaps suffix)")
    parser.add_argument("--time-col", default="timestamp",
                        help="Name of timestamp column (default: timestamp)")

    args = parser.parse_args()

    # Check inputs
    data_path = Path(args.data)
    if not data_path.exists():
        print(f"Error: Data file not found: {args.data}", file=sys.stderr)
        sys.exit(1)

    # Load data
    print(f"Loading data from {args.data} ...")
    if data_path.suffix == ".parquet":
        df = pd.read_parquet(data_path)
    elif data_path.suffix == ".csv":
        df = pd.read_csv(data_path)
    else:
        print(f"Error: Unsupported file type: {data_path.suffix}", file=sys.stderr)
        sys.exit(1)

    print(f"  Loaded {len(df):,} rows")

    # Mark session gaps
    print(f"Analyzing session log: {args.sessions} ...")
    df = mark_session_gaps(df, args.sessions, time_col=args.time_col)

    # Output path
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = data_path.with_stem(data_path.stem + "_with_gaps")

    # Write output
    print(f"Writing to {output_path} ...")
    if output_path.suffix == ".parquet":
        df.to_parquet(output_path, index=False)
    elif output_path.suffix == ".csv":
        df.to_csv(output_path, index=False)
    else:
        print(f"Error: Unsupported output type: {output_path.suffix}", file=sys.stderr)
        sys.exit(1)

    # Summary
    session_gap_count = df["is_session_gap"].sum()
    session_gap_pct = session_gap_count / len(df) * 100 if len(df) > 0 else 0

    print()
    print("Summary:")
    print(f"  Total rows:       {len(df):,}")
    print(f"  Session gaps:     {session_gap_count:,} ({session_gap_pct:.1f}%)")
    print(f"  Active session:   {len(df) - session_gap_count:,} ({100 - session_gap_pct:.1f}%)")

    # If there's an is_gap column, show breakdown
    if "is_gap" in df.columns:
        print()
        print("Gap breakdown:")
        data_gaps = df["is_gap"].sum()
        expected_gaps = (df["is_gap"] & df["is_session_gap"]).sum()
        unexpected_gaps = (df["is_gap"] & ~df["is_session_gap"]).sum()

        print(f"  Total data gaps:     {data_gaps:,}")
        print(f"  Expected gaps:       {expected_gaps:,} (pipeline not running)")
        print(f"  Unexpected gaps:     {unexpected_gaps:,} (pipeline running, no data)")

    print()
    print(f"✅ Saved to {output_path}")


if __name__ == "__main__":
    main()
