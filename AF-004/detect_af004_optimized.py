#!/usr/bin/env python3
"""
AF-004: VSS Purge Detection (Optimized for Filtered Data)

Works with pre-filtered VSS data from stream_filter_vss.py
Supports multiple formats: JSON-LD, N-Triples, Turtle

Usage:
    # Option 1: Filter first, then detect (recommended for large files)
    python3 stream_filter_vss.py --mft large_mft.jsonld --usn large_usn.jsonld --output-dir /tmp/vss/
    python3 detect_af004_optimized.py /tmp/vss/mft_vss_filtered.jsonld /tmp/vss/usn_vss_filtered.jsonld

    # Option 2: Direct detection on small files
    python3 detect_af004_optimized.py small_mft.jsonld small_usn.jsonld

    # Option 3: Use N-Triples (faster parsing)
    python3 stream_filter_vss.py --mft mft.jsonld --usn usn.jsonld --output-format nt
    python3 detect_af004_optimized.py /tmp/vss_filtered/mft_vss_filtered.nt /tmp/vss_filtered/usn_vss_filtered.nt --format nt
"""

import sys
import os
import argparse
from pathlib import Path
from rdflib import Dataset


def parse_args():
    parser = argparse.ArgumentParser(
        description="AF-004 VSS Purge Detection (optimized for filtered data)"
    )
    parser.add_argument(
        'mft_file',
        help="Path to MFT file (JSON-LD, N-Triples, or Turtle)"
    )
    parser.add_argument(
        'usn_file',
        help="Path to USN file"
    )
    parser.add_argument(
        '--format',
        choices=['json-ld', 'nt', 'ttl', 'auto'],
        default='auto',
        help="Input format (default: auto-detect from extension)"
    )
    parser.add_argument(
        '--rule-file',
        default='RULE_SIMPLE.rq',
        help="SPARQL rule file (default: RULE_SIMPLE.rq)"
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help="Show detailed loading information"
    )

    return parser.parse_args()


def detect_format(file_path: Path) -> str:
    """Auto-detect format from file extension."""
    ext = file_path.suffix.lower()
    format_map = {
        '.jsonld': 'json-ld',
        '.json': 'json-ld',
        '.nt': 'nt',
        '.ntriples': 'nt',
        '.ttl': 'ttl',
        '.turtle': 'ttl'
    }
    return format_map.get(ext, 'json-ld')


def main():
    args = parse_args()

    mft_file = Path(args.mft_file)
    usn_file = Path(args.usn_file)
    rule_file = Path(args.rule_file)

    # Validation
    if not mft_file.exists():
        print(f"ERROR: MFT file not found: {mft_file}", file=sys.stderr)
        return 1

    if not usn_file.exists():
        print(f"ERROR: USN file not found: {usn_file}", file=sys.stderr)
        return 1

    if not rule_file.exists():
        print(f"ERROR: Rule file not found: {rule_file}", file=sys.stderr)
        print(f"  Looking in current directory: {Path.cwd()}", file=sys.stderr)
        return 1

    # Detect format
    if args.format == 'auto':
        mft_format = detect_format(mft_file)
        usn_format = detect_format(usn_file)
    else:
        mft_format = usn_format = args.format

    print("=" * 60)
    print("AF-004: VSS Purge Detection (Optimized)")
    print("=" * 60)
    print()
    print(f"MFT File: {mft_file.name}")
    print(f"  Size: {mft_file.stat().st_size / (1024**2):.2f} MB")
    print(f"  Format: {mft_format}")
    print()
    print(f"USN File: {usn_file.name}")
    print(f"  Size: {usn_file.stat().st_size / (1024**2):.2f} MB")
    print(f"  Format: {usn_format}")
    print()
    print(f"Rule: {rule_file.name}")
    print()

    # Load SPARQL query
    query = rule_file.read_text()

    # Create dataset with named graphs
    print("=" * 60)
    print("Loading RDF Graphs")
    print("=" * 60)
    print()

    ds = Dataset()

    # Load MFT graph
    print(f"Loading MFT graph from {mft_file.name}...")
    mft_graph = ds.graph("urn:graph:mft")
    mft_graph.parse(mft_file, format=mft_format)
    print(f"  ✓ {len(mft_graph):,} triples loaded")

    # Load USN graph
    print(f"Loading USN graph from {usn_file.name}...")
    usn_graph = ds.graph("urn:graph:usn")
    usn_graph.parse(usn_file, format=usn_format)
    print(f"  ✓ {len(usn_graph):,} triples loaded")
    print()

    # Execute query
    print("=" * 60)
    print("Running AF-004 Detection Query")
    print("=" * 60)
    print()

    if args.verbose:
        print("Executing SPARQL query...")

    results = list(ds.query(query))

    # Report results
    print()
    if results:
        print("🚨 " + "=" * 58)
        print("   AF-004 ALERT: Volume Shadow Copy (VSS) Purge Detected!")
        print("=" * 60)
        print()
        print(f"Found {len(results)} contradiction(s):")
        print()

        for i, row in enumerate(results, 1):
            print(f"Contradiction #{i}:")
            print(f"  VSS Infrastructure: {row.vss_infrastructure}")
            print(f"  Deleted GUID:       {row.deleted_guid}")
            print(f"  USN Evidence:       {row.usn_evidence}")
            print()

        print("=" * 60)
        print("CONCLUSION:")
        print("  ✓ VSS infrastructure files exist in MFT")
        print("  ✓ GUID shadow copy directories were deleted")
        print("  ✓ USN Journal confirms GUID deletion operations")
        print()
        print("  → Anti-forensic activity detected: VSS purge")
        print("=" * 60)

        return 2  # Exit code 2 = detection positive

    else:
        print("✓ " + "=" * 58)
        print("   No VSS purge detected")
        print("=" * 60)
        print()
        print("Analysis:")
        print(f"  MFT triples: {len(mft_graph):,}")
        print(f"  USN triples: {len(usn_graph):,}")
        print()
        print("Possible reasons:")
        print("  • VSS infrastructure matches existing GUID directories")
        print("  • No USN deletion evidence found")
        print("  • System has not experienced VSS purge activity")
        print("=" * 60)

        return 0  # Exit code 0 = no detection

if __name__ == '__main__':
    sys.exit(main())
