#!/usr/bin/env python3
"""
Generate labels for timeseries cert files.
Downloads phishing feeds (OpenPhish, URLhaus) and Tranco data, then labels all domains.

Environment variables:
  URLHAUS_API_KEY - Optional API key for URLhaus (get from https://urlhaus.abuse.ch/)
"""

import json
import logging
import os
import sys
from pathlib import Path
from urllib.request import urlopen, Request
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("generate-labels")

OPENPHISH_URL = "https://openphish.com/feed.txt"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

def download_openphish():
    """Download and parse OpenPhish feed (free, no registration required)."""
    cache_file = Path("sources/cache/openphish_cache.txt")
    cache_file.parent.mkdir(parents=True, exist_ok=True)

    if cache_file.exists():
        age_hours = (datetime.now().timestamp() - cache_file.stat().st_mtime) / 3600
        if age_hours < 6:  # OpenPhish updates every few hours
            log.info(f"Using cached OpenPhish data ({age_hours:.1f}h old)")
            return parse_openphish(cache_file)

    log.info("Downloading OpenPhish feed (free public feed)...")
    try:
        req = Request(OPENPHISH_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=30) as resp:
            data = resp.read().decode("utf-8")
        cache_file.write_text(data)
        log.info(f"OpenPhish saved to {cache_file}")
        return parse_openphish(cache_file)
    except Exception as e:
        log.error(f"OpenPhish download failed: {e}")
        if cache_file.exists():
            log.info("Using stale cache")
            return parse_openphish(cache_file)
        return set()

def parse_openphish(txt_file):
    """Parse OpenPhish feed and extract domains with URLs."""
    domain_to_url = {}  # Map domain -> full URL
    lines = Path(txt_file).read_text().strip().split("\n")
    for line in lines:
        if not line or line.startswith("#"):
            continue
        full_url = line.strip()
        # Extract domain from URL
        url_part = full_url.split("://", 1)[1] if "://" in full_url else full_url
        domain = url_part.split("/")[0].split(":")[0].lower()
        if domain:
            # Keep the first URL seen for each domain
            if domain not in domain_to_url:
                domain_to_url[domain] = full_url

    log.info(f"OpenPhish: {len(domain_to_url)} unique phishing domains")
    return domain_to_url

def download_urlhaus():
    """Download and parse URLhaus feed (abuse.ch - requires API key)."""
    cache_file = Path("sources/cache/urlhaus_cache.json")
    cache_file.parent.mkdir(parents=True, exist_ok=True)

    # Check for API key
    api_key = os.environ.get("URLHAUS_API_KEY")
    if not api_key:
        log.warning("URLhaus API key not set (export URLHAUS_API_KEY='your_key')")
        log.warning("Skipping URLhaus - using only OpenPhish")
        return {}

    if cache_file.exists():
        age_hours = (datetime.now().timestamp() - cache_file.stat().st_mtime) / 3600
        if age_hours < 6:  # URLhaus updates frequently
            log.info(f"Using cached URLhaus data ({age_hours:.1f}h old)")
            return parse_urlhaus(cache_file)

    log.info("Downloading URLhaus feed (abuse.ch - malware/phishing URLs)...")
    try:
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Auth-Key": api_key
        }
        req = Request(URLHAUS_URL, headers=headers)
        with urlopen(req, timeout=30) as resp:
            data = resp.read().decode("utf-8")
        cache_file.write_text(data)
        log.info(f"URLhaus saved to {cache_file}")
        return parse_urlhaus(cache_file)
    except Exception as e:
        log.error(f"URLhaus download failed: {e}")
        log.error("Check your API key at https://urlhaus.abuse.ch/")
        if cache_file.exists():
            log.info("Using stale cache")
            return parse_urlhaus(cache_file)
        return {}

def parse_urlhaus(json_file):
    """Parse URLhaus JSON feed and extract domains with URLs."""
    domain_to_url = {}
    try:
        data = json.loads(Path(json_file).read_text())

        if data.get("query_status") != "ok":
            log.warning(f"URLhaus query status: {data.get('query_status')}")
            return {}

        urls = data.get("urls", [])
        if not urls:
            log.warning("URLhaus returned no URLs")
            return {}

        for entry in urls:
            if not entry:
                continue

            full_url = entry.get("url", "")
            if not full_url:
                continue

            # Filter for phishing-related threats
            threat = entry.get("threat", "").lower()

            # Handle tags being None (null in JSON)
            tags_raw = entry.get("tags")
            tags = [t.lower() for t in tags_raw] if tags_raw else []

            # Only include if marked as phishing or credential stealer
            is_phishing = (
                "phishing" in threat or
                "phishing" in tags or
                "credential" in tags or
                "stealer" in threat
            )

            if not is_phishing:
                continue

            # Extract domain from URL
            try:
                url_part = full_url.split("://", 1)[1] if "://" in full_url else full_url
                domain = url_part.split("/")[0].split(":")[0].lower()

                # Skip IP addresses (we want domain names)
                if domain and not all(c.isdigit() or c == '.' for c in domain):
                    if domain not in domain_to_url:
                        domain_to_url[domain] = full_url
            except:
                continue

        log.info(f"URLhaus: {len(domain_to_url)} unique phishing domains")
    except Exception as e:
        log.error(f"Failed to parse URLhaus data: {e}")
        import traceback
        log.error(traceback.format_exc())

    return domain_to_url

def load_existing_phishing_labels():
    """Load phishing domains from existing project label files."""
    domain_to_url = {}  # Map domain -> URL

    # Check for existing phishing labels in sources/raw
    label_files = [
        "sources/raw/labels_streaming_48h.jsonl",
        "sources/raw/phishing_labels.jsonl",
        "sources/raw/labels_historial.jsonl"
    ]

    for label_file in label_files:
        path = Path(label_file)
        if not path.exists():
            continue

        log.info(f"Loading existing phishing labels from {label_file}...")
        try:
            with open(path, "r") as f:
                for line in f:
                    try:
                        record = json.loads(line)
                        if record.get("y") == 1 or record.get("label_source") == "phishtank":
                            domain = record.get("domain", "").lower()
                            url = record.get("url")
                            if domain and domain not in domain_to_url:
                                domain_to_url[domain] = url
                    except:
                        continue
            log.info(f"  Loaded {len(domain_to_url)} phishing domains from {label_file}")
        except Exception as e:
            log.warning(f"  Failed to load {label_file}: {e}")

    return domain_to_url

def download_tranco():
    """Download and parse Tranco top-10k."""
    cache_file = Path("sources/cache/tranco_top10k.txt")
    cache_file.parent.mkdir(parents=True, exist_ok=True)

    if cache_file.exists():
        age_hours = (datetime.now().timestamp() - cache_file.stat().st_mtime) / 3600
        if age_hours < 168:  # 1 week
            log.info(f"Using cached Tranco data ({age_hours:.1f}h old)")
            domains = set(Path(cache_file).read_text().strip().split("\n"))
            log.info(f"Tranco: {len(domains)} top domains")
            return domains

    log.info("Downloading Tranco top-1M (using only top-10k)...")
    try:
        import zipfile
        import io

        req = Request(TRANCO_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=60) as resp:
            zip_data = resp.read()

        with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
            csv_name = z.namelist()[0]
            with z.open(csv_name) as f:
                lines = f.read().decode("utf-8").strip().split("\n")

        # Extract top 10k domains
        top10k = set()
        for line in lines[:10000]:
            if "," in line:
                _, domain = line.split(",", 1)
                top10k.add(domain.strip().lower())

        cache_file.write_text("\n".join(sorted(top10k)))
        log.info(f"Tranco saved to {cache_file}: {len(top10k)} domains")
        return top10k
    except Exception as e:
        log.warning(f"Tranco download failed: {e}")
        return set()

def extract_domains_from_certs(cert_file):
    """Extract unique domains from cert JSONL file."""
    domains = set()
    with open(cert_file, "r") as f:
        for line in f:
            try:
                record = json.loads(line)
                for domain in record.get("domains", []):
                    domains.add(domain.lower())
            except:
                continue

    log.info(f"Extracted {len(domains)} unique domains from {cert_file}")
    return domains

def generate_labels(domains, phishing_map, tranco_set, output_file):
    """Generate label file.

    Args:
        domains: Set of domains to label
        phishing_map: Dict mapping domain -> (URL, source) for phishing domains
        tranco_set: Set of legitimate domains
        output_file: Output path
    """
    labels = []
    phishing_count = 0
    tranco_count = 0
    unknown_count = 0

    for domain in sorted(domains):
        if domain in phishing_map:
            y = 1
            # phishing_map values are now (url, source) tuples
            url, label_source = phishing_map[domain]
            phishing_count += 1
        elif domain in tranco_set:
            y = 0
            label_source = "tranco"
            url = None
            tranco_count += 1
        else:
            y = 0
            label_source = "unknown"
            url = None
            unknown_count += 1

        labels.append({
            "domain": domain,
            "url": url,
            "y": y,
            "label_source": label_source,
            "label_ts": datetime.now(timezone.utc).isoformat()
        })

    # Write to output
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        for label in labels:
            f.write(json.dumps(label) + "\n")

    log.info(f"Saved {len(labels)} labels to {output_file}")
    log.info(f"  Phishing: {phishing_count}, Tranco: {tranco_count}, Unknown: {unknown_count}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python generate_timeseries_labels.py <certs_file> <output_labels_file>")
        sys.exit(1)

    cert_file = sys.argv[1]
    output_file = sys.argv[2]

    if not Path(cert_file).exists():
        log.error(f"Cert file not found: {cert_file}")
        sys.exit(1)

    log.info("="*80)
    log.info("GENERATING LABELS")
    log.info("="*80)

    # Download label sources
    log.info("\n1. Loading phishing domains from multiple sources...")
    phishing_map = {}  # domain -> (URL, source) mapping
    source_counts = {}

    # Source 1: OpenPhish (free public feed)
    openphish_map = download_openphish()
    source_counts['openphish'] = len(openphish_map)
    for domain, url in openphish_map.items():
        phishing_map[domain] = (url, "openphish")

    # Source 2: URLhaus (abuse.ch - malware/phishing URLs)
    urlhaus_map = download_urlhaus()
    source_counts['urlhaus'] = len(urlhaus_map)
    for domain, url in urlhaus_map.items():
        if domain not in phishing_map:
            phishing_map[domain] = (url, "urlhaus")

    # Source 3: Existing project labels (if any)
    existing_phishing_map = load_existing_phishing_labels()
    source_counts['existing'] = len(existing_phishing_map)
    if existing_phishing_map:
        log.info(f"Found {len(existing_phishing_map)} existing phishing labels in project")
        # Only add if not already in other sources
        for domain, url in existing_phishing_map.items():
            if domain not in phishing_map:
                source = "phishtank" if url else "existing"
                phishing_map[domain] = (url, source)

    log.info(f"✅ Total unique phishing domains: {len(phishing_map)}")
    log.info(f"   Sources: OpenPhish={source_counts['openphish']}, URLhaus={source_counts['urlhaus']}, Existing={source_counts['existing']}")

    # Download legitimate domain list
    log.info("\n2. Loading legitimate domains (Tranco top-10k)...")
    tranco_set = download_tranco()

    # Extract domains from certs
    log.info("\n3. Extracting domains from cert file...")
    domains = extract_domains_from_certs(cert_file)

    # Generate labels
    log.info("\n4. Generating labels...")
    generate_labels(domains, phishing_map, tranco_set, output_file)

    log.info("\n" + "="*80)
    log.info("✅ COMPLETE")
    log.info("="*80)

if __name__ == "__main__":
    main()
