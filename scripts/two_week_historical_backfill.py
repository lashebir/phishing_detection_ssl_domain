#!/usr/bin/env python3
"""
CT Log Historical Backfill
===========================
Collects historical CT log data for time series analysis.
Finds the CT log index corresponding to a target start date,
then polls forward sampling up to MAX_PER_HOUR certs per hour.

This keeps total volume manageable (336k records for 2 weeks)
while ensuring every hourly window has enough certs for stable
aggregate features (entropy, tld_risk, san_count, etc.)

Install:
    pip install requests cryptography

Run:
    # collect last 2 weeks (default)
    python ct_backfill.py

    # collect last N days
    python ct_backfill.py --days 7

    # resume interrupted run
    python ct_backfill.py --resume

    # collect specific date range
    python ct_backfill.py --start 2026-05-01 --end 2026-05-15
"""

import argparse
import base64
import json
import logging
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# ── Config ────────────────────────────────────────────────────────────────────

CT_LOG_URL    = "https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1"
OUTPUT_FILE   = "data/timeseries/certs_historical.jsonl"
STATE_FILE    = "ct_backfill_state.json"
BATCH_SIZE    = 256
POLL_DELAY    = 1.0       # seconds between batches
MAX_PER_HOUR  = 1000      # max certs to keep per calendar hour
DEFAULT_DAYS  = 14        # how far back to go by default

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("ct-backfill")

# ── Stats ─────────────────────────────────────────────────────────────────────

stats = {
    "fetched": 0, "parsed": 0, "written": 0,
    "skipped_quota": 0, "errors": 0,
    "start_time": time.time(),
}

def print_stats(current_index: int = 0, end_index: int = 0):
    elapsed  = time.time() - stats["start_time"]
    rate     = stats["fetched"] / elapsed if elapsed else 0
    progress = (current_index - stats.get("start_index", current_index)) / \
               max(end_index - stats.get("start_index", current_index), 1) * 100
    eta_secs = (end_index - current_index) / (stats["fetched"] / elapsed + 1e-9) \
               if elapsed and stats["fetched"] else 0
    eta_hrs  = eta_secs / 3600

    log.info(
        "fetched:%d written:%d skipped:%d errors:%d rate:%.1f/s "
        "progress:%.1f%% eta:%.1fhr",
        stats["fetched"], stats["written"], stats["skipped_quota"],
        stats["errors"], rate, progress, eta_hrs,
    )


# ── CT log API ────────────────────────────────────────────────────────────────

def get_tree_size() -> int:
    resp = requests.get(f"{CT_LOG_URL}/get-sth", timeout=10)
    resp.raise_for_status()
    size = resp.json()["tree_size"]
    log.info("CT log tree size: %d", size)
    return size


def get_entries(start: int, end: int) -> list[dict]:
    resp = requests.get(
        f"{CT_LOG_URL}/get-entries",
        params={"start": start, "end": end},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("entries", [])


def timestamp_to_index(target_ts: float, tree_size: int) -> int:
    """Binary search CT log to find index closest to target_ts (Unix seconds)."""
    lo, hi = 0, tree_size - 1
    log.info("Binary searching for index at ts=%s …",
             datetime.fromtimestamp(target_ts, tz=timezone.utc).isoformat())

    for _ in range(30):
        if lo >= hi:
            break
        mid = (lo + hi) // 2
        try:
            entries = get_entries(mid, mid)
            if not entries:
                break
            leaf     = base64.b64decode(entries[0]["leaf_input"])
            entry_ts = int.from_bytes(leaf[2:10], "big") / 1000.0
            if entry_ts < target_ts:
                lo = mid + 1
            else:
                hi = mid
        except Exception as exc:
            log.debug("Binary search error at %d: %s", mid, exc)
            break
        time.sleep(0.1)

    log.info("Found start index: %d", lo)
    return lo


# ── Certificate parser ────────────────────────────────────────────────────────

def parse_entry(entry: dict, index: int) -> dict | None:
    try:
        leaf       = base64.b64decode(entry["leaf_input"])
        entry_type = int.from_bytes(leaf[10:12], "big")

        if entry_type == 1:
            extra = base64.b64decode(entry.get("extra_data", ""))
            if len(extra) < 3:
                return None
            cert_len = int.from_bytes(extra[:3], "big")
            der      = extra[3:3 + cert_len]
        else:
            cert_len = int.from_bytes(leaf[12:15], "big")
            der      = leaf[15:15 + cert_len]

        cert = x509.load_der_x509_certificate(der, default_backend())

        try:
            san     = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            domains = san.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            domains = []

        if not domains:
            try:
                cn      = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                domains = [cn[0].value] if cn else []
            except Exception:
                return None

        if not domains:
            return None

        def attr(name, oid):
            try:
                a = name.get_attributes_for_oid(oid)
                return a[0].value if a else None
            except Exception:
                return None

        oid         = x509.oid.NameOID
        not_before  = cert.not_valid_before_utc.timestamp()

        return {
            "schema_version": 1,
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "cert_index": index,
            "not_before": not_before,
            "not_after":  cert.not_valid_after_utc.timestamp(),
            "domains":    list(domains),
            "subject": {
                "CN": attr(cert.subject, oid.COMMON_NAME),
                "O":  attr(cert.subject, oid.ORGANIZATION_NAME),
            },
            "issuer": {
                "CN":         attr(cert.issuer, oid.COMMON_NAME),
                "O":          attr(cert.issuer, oid.ORGANIZATION_NAME),
                "aggregated": cert.issuer.rfc4514_string(),
            },
            "source":      {"name": "Google 'Argon2026h1' log", "url": CT_LOG_URL},
            "data_source": "ct_historical_backfill",
        }
    except Exception as exc:
        stats["errors"] += 1
        log.debug("Parse error at index %d: %s", index, exc)
        return None


# ── State persistence ─────────────────────────────────────────────────────────

def save_state(current_index: int, end_index: int, hourly_counts: dict):
    state = {
        "current_index":  current_index,
        "end_index":      end_index,
        "hourly_counts":  dict(hourly_counts),
        "stats":          {k: v for k, v in stats.items() if k != "start_time"},
        "saved_at":       datetime.now(timezone.utc).isoformat(),
    }
    Path(STATE_FILE).write_text(json.dumps(state, indent=2))


def load_state() -> dict | None:
    if not Path(STATE_FILE).exists():
        return None
    try:
        return json.loads(Path(STATE_FILE).read_text())
    except Exception:
        return None


# ── Shutdown ──────────────────────────────────────────────────────────────────

_running      = True
_current_idx  = 0
_end_idx      = 0
_hourly       = defaultdict(int)


def shutdown(sig, frame):
    global _running
    log.info("Shutting down — saving state …")
    _running = False
    save_state(_current_idx, _end_idx, _hourly)
    print_stats(_current_idx, _end_idx)
    log.info("State saved to %s — run with --resume to continue", STATE_FILE)
    sys.exit(0)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global _running, _current_idx, _end_idx, _hourly

    parser = argparse.ArgumentParser(description="CT log historical backfill for time series")
    parser.add_argument("--days",        type=int,   default=DEFAULT_DAYS,
                        help=f"Days of history to collect (default: {DEFAULT_DAYS})")
    parser.add_argument("--start",       type=str,   default=None,
                        help="Start date YYYY-MM-DD (overrides --days)")
    parser.add_argument("--end",         type=str,   default=None,
                        help="End date YYYY-MM-DD (default: now)")
    parser.add_argument("--output",      type=str,   default=OUTPUT_FILE,
                        help=f"Output JSONL file (default: {OUTPUT_FILE})")
    parser.add_argument("--max-per-hour",type=int,   default=MAX_PER_HOUR,
                        help=f"Max certs to keep per hour (default: {MAX_PER_HOUR})")
    parser.add_argument("--resume",      action="store_true",
                        help="Resume from saved state file")
    parser.add_argument("--estimate",    action="store_true",
                        help="Estimate volume and runtime without collecting")
    args = parser.parse_args()

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Resolve time range ────────────────────────────────────────────────────

    tree_size = get_tree_size()

    if args.resume:
        state = load_state()
        if not state:
            log.error("No state file found at %s — cannot resume", STATE_FILE)
            sys.exit(1)
        start_index  = state["current_index"]
        end_index    = state["end_index"]
        _hourly      = defaultdict(int, state["hourly_counts"])
        log.info("Resuming from index %d → %d (%d remaining)",
                 start_index, end_index, end_index - start_index)
    else:
        # Resolve start timestamp
        if args.start:
            start_dt = datetime.strptime(args.start, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        else:
            start_dt = datetime.now(timezone.utc) - timedelta(days=args.days)

        # Resolve end timestamp
        if args.end:
            end_dt = datetime.strptime(args.end, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        else:
            end_dt = datetime.now(timezone.utc)

        log.info("Collecting %s → %s", start_dt.date(), end_dt.date())

        start_index = timestamp_to_index(start_dt.timestamp(), tree_size)
        end_index   = timestamp_to_index(end_dt.timestamp(),   tree_size)

    # ── Volume estimate ───────────────────────────────────────────────────────

    total_entries   = end_index - start_index
    hours_in_range  = (end_index - start_index) / (tree_size / (24 * 365)) / 24
    max_records     = int(hours_in_range) * args.max_per_hour
    est_batches     = total_entries / BATCH_SIZE
    est_hours       = est_batches * POLL_DELAY / 3600

    log.info("Range:        %d → %d (%d entries)", start_index, end_index, total_entries)
    log.info("Max records:  ~%d (%d/hr × %.0fh)", max_records, args.max_per_hour, hours_in_range)
    log.info("Est. runtime: %.1f hours (resumable)", est_hours)
    log.info("Est. size:    ~%.0f MB", max_records * 500 / 1_000_000)

    if args.estimate:
        log.info("--estimate flag set — exiting without collecting")
        return

    # ── Output file ───────────────────────────────────────────────────────────

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.resume else "w"
    if not args.resume and Path(args.output).exists():
        log.warning("Output file exists — overwriting. Use --resume to append.")

    # ── Collection loop ───────────────────────────────────────────────────────

    _current_idx = start_index
    _end_idx     = end_index
    stats["start_index"] = start_index

    log.info("Starting collection — output: %s (mode: %s)", args.output, mode)

    with open(args.output, mode, buffering=1) as out:
        while _running and _current_idx < end_index:
            batch_end = min(_current_idx + BATCH_SIZE - 1, end_index - 1)

            try:
                entries = get_entries(_current_idx, batch_end)
            except requests.RequestException as exc:
                log.warning("API error: %s — retrying in 10s", exc)
                time.sleep(10)
                continue

            if not entries:
                log.info("No entries at index %d — waiting …", _current_idx)
                time.sleep(5)
                continue

            for i, entry in enumerate(entries):
                stats["fetched"] += 1
                record = parse_entry(entry, _current_idx + i)
                if not record:
                    continue

                stats["parsed"] += 1

                # ── Hourly quota check ────────────────────────────────────────
                # Bucket by the cert's issuance hour (not_before), not ingest time.
                # This ensures time series windows reflect when certs were issued.
                cert_hour = datetime.fromtimestamp(
                    record["not_before"], tz=timezone.utc
                ).strftime("%Y%m%d%H")

                if _hourly[cert_hour] >= args.max_per_hour:
                    stats["skipped_quota"] += 1
                    continue

                _hourly[cert_hour] += 1
                out.write(json.dumps(record, default=str) + "\n")
                stats["written"] += 1

            _current_idx += len(entries)

            # Progress + state save every 10k fetched
            if stats["fetched"] % 10_000 == 0:
                print_stats(_current_idx, end_index)
                save_state(_current_idx, end_index, _hourly)

            time.sleep(POLL_DELAY)

    # ── Done ──────────────────────────────────────────────────────────────────

    print_stats(_current_idx, end_index)
    log.info("Collection complete")
    log.info("Written: %d records → %s", stats["written"], args.output)
    log.info("Unique hours covered: %d / %.0f", len(_hourly), hours_in_range)

    # Clean up state file on successful completion
    if _current_idx >= end_index and Path(STATE_FILE).exists():
        Path(STATE_FILE).unlink()
        log.info("State file removed (run complete)")

    print(f"\nLoad in notebook:")
    print(f"  df = pd.read_json('{args.output}', lines=True)")
    print(f"  df['timestamp'] = pd.to_datetime(df['not_before'], unit='s', utc=True)")


if __name__ == "__main__":
    main()