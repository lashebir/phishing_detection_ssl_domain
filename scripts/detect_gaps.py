#!/usr/bin/env python3
"""
Gap Detection Utility for Streaming Certificate Data

Analyzes collected certificate data to find:
1. Missing cert_index ranges (gaps in CT log collection)
2. Time gaps in streaming data (periods with no data collection)
3. Statistics about data coverage

Usage:
    python scripts/detect_gaps.py sources/raw/certs_streaming_48h.jsonl
    python scripts/detect_gaps.py --min-gap-size 100 --output gaps.json sources/raw/certs_streaming_48h.jsonl

Output:
    Prints gap report to stdout
    Optionally saves machine-readable gap list to JSON file
"""

import argparse
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Tuple


def load_cert_indices(filepath: str) -> Tuple[List[int], List[str]]:
    """
    Load cert_index and timestamp from JSONL file.
    Returns: (sorted_indices, sorted_timestamps)
    """
    records = []

    with open(filepath, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                record = json.loads(line)
                cert_index = record.get("cert_index")
                timestamp = record.get("timestamp")

                if cert_index is not None:
                    records.append((cert_index, timestamp))

            except json.JSONDecodeError:
                print(f"Warning: Skipping invalid JSON at line {line_num}", file=sys.stderr)
                continue

    # Sort by cert_index
    records.sort(key=lambda x: x[0])

    indices = [r[0] for r in records]
    timestamps = [r[1] for r in records]

    return indices, timestamps


def find_index_gaps(indices: List[int], min_gap_size: int = 1) -> List[Dict]:
    """
    Find gaps in cert_index sequence.

    Returns list of gaps: [{"start": N, "end": M, "size": K}, ...]
    """
    if not indices:
        return []

    gaps = []

    for i in range(len(indices) - 1):
        current = indices[i]
        next_idx = indices[i + 1]

        gap_size = next_idx - current - 1

        if gap_size >= min_gap_size:
            gaps.append({
                "start": current + 1,
                "end": next_idx - 1,
                "size": gap_size
            })

    return gaps


def find_time_gaps(timestamps: List[str], max_gap_minutes: int = 10) -> List[Dict]:
    """
    Find time gaps in streaming data collection.

    A gap is defined as a period > max_gap_minutes with no data.

    Returns list of time gaps with start/end timestamps and duration.
    """
    if not timestamps or len(timestamps) < 2:
        return []

    gaps = []
    max_gap_delta = timedelta(minutes=max_gap_minutes)

    for i in range(len(timestamps) - 1):
        try:
            current = datetime.fromisoformat(timestamps[i].replace('Z', '+00:00'))
            next_ts = datetime.fromisoformat(timestamps[i + 1].replace('Z', '+00:00'))

            gap_duration = next_ts - current

            if gap_duration > max_gap_delta:
                gaps.append({
                    "start": timestamps[i],
                    "end": timestamps[i + 1],
                    "duration_minutes": gap_duration.total_seconds() / 60,
                    "duration_str": str(gap_duration)
                })
        except (ValueError, AttributeError):
            continue

    return gaps


def print_report(filepath: str, indices: List[int], timestamps: List[str],
                 index_gaps: List[Dict], time_gaps: List[Dict]):
    """Print human-readable gap report."""

    print("=" * 80)
    print("CT LOG GAP DETECTION REPORT")
    print("=" * 80)
    print()
    print(f"Data file: {filepath}")
    print()

    # Overall statistics
    print("── Data Coverage ──")
    print(f"  Total records:        {len(indices):,}")

    if indices:
        print(f"  First cert_index:     {indices[0]:,}")
        print(f"  Last cert_index:      {indices[-1]:,}")
        print(f"  Index range span:     {indices[-1] - indices[0] + 1:,}")
        print(f"  Expected records:     {indices[-1] - indices[0] + 1:,}")
        print(f"  Missing records:      {(indices[-1] - indices[0] + 1) - len(indices):,}")

        coverage_pct = len(indices) / (indices[-1] - indices[0] + 1) * 100
        print(f"  Coverage:             {coverage_pct:.2f}%")

    print()

    if timestamps:
        try:
            first_ts = datetime.fromisoformat(timestamps[0].replace('Z', '+00:00'))
            last_ts = datetime.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
            duration = last_ts - first_ts

            print("── Time Coverage ──")
            print(f"  First timestamp:      {first_ts.isoformat()}")
            print(f"  Last timestamp:       {last_ts.isoformat()}")
            print(f"  Collection duration:  {duration}")
            print(f"  Avg rate:             {len(indices) / duration.total_seconds():.1f} certs/sec")
            print()
        except (ValueError, AttributeError):
            pass

    # Index gaps
    print("── Missing CT Log Index Ranges ──")
    if not index_gaps:
        print("  ✅ No gaps found — continuous coverage!")
    else:
        print(f"  ⚠️  Found {len(index_gaps)} gaps:")
        print()

        total_missing = sum(g["size"] for g in index_gaps)
        print(f"  Total missing entries: {total_missing:,}")
        print()

        # Show largest gaps
        sorted_gaps = sorted(index_gaps, key=lambda x: x["size"], reverse=True)
        top_gaps = sorted_gaps[:10]

        print("  Top 10 largest gaps:")
        for i, gap in enumerate(top_gaps, 1):
            print(f"    {i:2d}. Index {gap['start']:,} → {gap['end']:,}  "
                  f"({gap['size']:,} missing entries)")

        if len(index_gaps) > 10:
            print(f"    ... and {len(index_gaps) - 10} more gaps")

    print()

    # Time gaps
    print("── Time Gaps (Collection Interruptions) ──")
    if not time_gaps:
        print("  ✅ No significant time gaps found")
    else:
        print(f"  ⚠️  Found {len(time_gaps)} time gaps:")
        print()

        for i, gap in enumerate(time_gaps, 1):
            print(f"    {i:2d}. {gap['duration_str']} gap")
            print(f"        From: {gap['start']}")
            print(f"        To:   {gap['end']}")

    print()
    print("=" * 80)


def save_gaps_json(output_path: str, index_gaps: List[Dict], time_gaps: List[Dict]):
    """Save gaps to JSON file for programmatic use."""
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "index_gaps": index_gaps,
        "time_gaps": time_gaps,
        "summary": {
            "index_gaps_count": len(index_gaps),
            "total_missing_indices": sum(g["size"] for g in index_gaps),
            "time_gaps_count": len(time_gaps)
        }
    }

    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"📝 Saved gap report to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Detect gaps in streaming certificate data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument("input", help="Input JSONL file with certificate data")
    parser.add_argument("--min-gap-size", type=int, default=1,
                        help="Minimum gap size to report (default: 1)")
    parser.add_argument("--max-time-gap", type=int, default=10,
                        help="Maximum expected time between records in minutes (default: 10)")
    parser.add_argument("-o", "--output",
                        help="Save machine-readable gap report to JSON file")

    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading data from {args.input} ...", file=sys.stderr)
    indices, timestamps = load_cert_indices(args.input)

    if not indices:
        print("Error: No valid cert_index values found in file", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing {len(indices):,} records ...", file=sys.stderr)
    print(file=sys.stderr)

    # Find gaps
    index_gaps = find_index_gaps(indices, min_gap_size=args.min_gap_size)
    time_gaps = find_time_gaps(timestamps, max_gap_minutes=args.max_time_gap)

    # Print report
    print_report(args.input, indices, timestamps, index_gaps, time_gaps)

    # Save JSON if requested
    if args.output:
        save_gaps_json(args.output, index_gaps, time_gaps)

    # Exit with error code if gaps found (useful for scripts)
    if index_gaps:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
