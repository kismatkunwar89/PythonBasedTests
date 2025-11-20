#!/usr/bin/env python3
"""
AF-TIMESTOMPING: Timestamp Manipulation Detection (Optimized)

Detects timestamp manipulation by comparing LNK target metadata with MFT records.
Works with pre-filtered data from stream_filter_timestomp.py or original files.

Usage:
    # Option 1: Filter first, then detect (recommended for large files)
    python3 stream_filter_timestomp.py --mft X --lnk Y --output-dir /tmp/timestomp/
    python3 detect_timestomp_optimized.py /tmp/timestomp/

    # Option 2: Direct detection on small files
    python3 detect_timestomp_optimized.py --mft small_mft.jsonld --lnk small_lnk.jsonld

    # Option 3: Specify files individually
    python3 detect_timestomp_optimized.py \
      --mft /tmp/timestomp/mft_lnk_filtered.jsonld \
      --lnk /tmp/timestomp/lnk_files.jsonld
"""

import sys
import argparse
from pathlib import Path
from rdflib import Dataset
from datetime import datetime


def parse_args():
    parser = argparse.ArgumentParser(
        description="AF-TIMESTOMPING: Timestamp manipulation detection (optimized for filtered data)"
    )

    # Accept either a directory or individual files
    parser.add_argument(
        'filter_dir',
        nargs='?',
        help="Directory containing filtered files (from stream_filter_timestomp.py)"
    )
    parser.add_argument(
        '--mft',
        help="Path to MFT file (JSON-LD)"
    )
    parser.add_argument(
        '--lnk',
        help="Path to LNK file (JSON-LD)"
    )
    parser.add_argument(
        '--rule-file',
        default='rule_optimized.rq',
        help="SPARQL rule file (default: rule_optimized.rq)"
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help="Show detailed loading information"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    # Determine file paths
    if args.filter_dir:
        filter_dir = Path(args.filter_dir)
        mft_file = filter_dir / "mft_lnk_filtered.jsonld"
        lnk_file = filter_dir / "lnk_files.jsonld"
    else:
        mft_file = Path(args.mft) if args.mft else None
        lnk_file = Path(args.lnk) if args.lnk else None

    # Validation
    if not mft_file or not mft_file.exists():
        print(f"ERROR: MFT file not found: {mft_file}", file=sys.stderr)
        return 1

    if not lnk_file or not lnk_file.exists():
        print(f"ERROR: LNK file not found: {lnk_file}", file=sys.stderr)
        return 1

    rule_file = Path(args.rule_file)
    if not rule_file.exists():
        print(f"ERROR: Rule file not found: {rule_file}", file=sys.stderr)
        print(f"  Looking in current directory: {Path.cwd()}", file=sys.stderr)
        return 1

    print("=" * 70)
    print("AF-TIMESTOMPING: Timestamp Manipulation Detection (Optimized)")
    print("=" * 70)
    print()
    print(f"MFT File: {mft_file.name}")
    print(f"  Size: {mft_file.stat().st_size / (1024**2):.2f} MB")
    print()
    print(f"LNK File: {lnk_file.name}")
    print(f"  Size: {lnk_file.stat().st_size / (1024**2):.2f} MB")
    print()
    print(f"Rule: {rule_file.name}")
    print()

    # Load SPARQL query
    query = rule_file.read_text()

    # Create dataset
    print("=" * 70)
    print("Loading RDF Data")
    print("=" * 70)
    print()

    ds = Dataset()

    # Load MFT data
    print(f"Loading MFT data from {mft_file.name}...")
    ds.parse(mft_file, format='json-ld')
    print(f"  ✓ Loaded")

    # Load LNK data
    print(f"Loading LNK data from {lnk_file.name}...")
    ds.parse(lnk_file, format='json-ld')
    print(f"  ✓ Loaded")

    total_triples = len(ds)
    print(f"\n  Total triples: {total_triples:,}")
    print()

    # Execute query
    print("=" * 70)
    print("Running AF-TIMESTOMPING Detection Query")
    print("=" * 70)
    print()

    if args.verbose:
        print("Executing SPARQL query...")

    results = list(ds.query(query))

    # Analyze results
    print()
    if results:
        print("🚨 " + "=" * 68)
        print("   AF-TIMESTOMPING ALERT: Timestamp Manipulation Detected!")
        print("=" * 70)
        print()
        print(f"Found {len(results)} timestomping instance(s):")
        print()

        timestomp_count = 0

        for i, row in enumerate(results, 1):
            # Extract variables from SPARQL result
            lnk_path = str(row.lnkFile) if hasattr(row, 'lnkFile') else "Unknown"
            target_path = str(row.lnkTargetPath) if hasattr(row, 'lnkTargetPath') else "Unknown"
            lnk_created_str = str(row.lnkTargetCreated) if hasattr(row, 'lnkTargetCreated') else ""
            mft_si_str = str(row.mftSiCreated) if hasattr(row, 'mftSiCreated') else ""
            mft_fn_str = str(row.mftFnCreated) if hasattr(row, 'mftFnCreated') else ""

            # Parse timestamps using datetime (no isodate needed for ISO format)
            try:
                from datetime import datetime as dt
                lnk_sc_str = str(row.lnkShortcutCreated) if hasattr(row, 'lnkShortcutCreated') else ""

                lnk_dt = dt.fromisoformat(lnk_created_str.replace('Z', '+00:00'))
                si_dt = dt.fromisoformat(mft_si_str.replace('Z', '+00:00'))
                fn_dt = dt.fromisoformat(mft_fn_str.replace('Z', '+00:00'))

                # Parse LNK shortcut created time if available
                lnk_sc_dt = None
                if lnk_sc_str:
                    lnk_sc_dt = dt.fromisoformat(lnk_sc_str.replace('Z', '+00:00'))

                # Calculate differences
                si_fn_diff = abs((si_dt - fn_dt).total_seconds())

                # False positive filtering done in SPARQL query (rule_optimized.rq)
                # SPARQL checks: lnkShortcutCreated ≈ mftFnCreated (within seconds)

                timestomp_count += 1

                print(f"{timestomp_count}. Timestamp Manipulation Detected")
                print(f"   Target File: {target_path}")
                print(f"   LNK Path: {lnk_path}")
                print()
                print(f"   Timestamps:")
                if lnk_sc_dt:
                    print(f"     LNK Shortcut Created: {lnk_sc_str}")
                print(f"     LNK Target Created:   {lnk_created_str}")
                print(f"     MFT $SI Created:      {mft_si_str}")
                print(f"     MFT $FN Created:      {mft_fn_str}")
                print()
                print(f"   🚨 EVIDENCE:")
                print(f"     • $SI differs from $FN by {si_fn_diff:.1f} seconds")
                if lnk_sc_dt:
                    lnk_sc_fn_diff = abs((lnk_sc_dt - fn_dt).total_seconds())
                    print(f"     • LNK Shortcut matches $FN (diff: {lnk_sc_fn_diff:.1f}s)")
                    print(f"     • Shortcut captured ORIGINAL time, $SI was modified")
                else:
                    print(f"     • This indicates $STANDARD_INFORMATION was tampered")
                print(f"     • MFT timestamp differs from LNK recorded timestamp")
                print()
            except Exception as e:
                print(f"Error parsing dates for {target_path}: {e}")
                continue
        print("CONCLUSION:")
        print("  ✓ LNK files preserve original target creation timestamps")
        print("  ✓ MFT $STANDARD_INFORMATION shows modified timestamps")
        print()
        print("  → Anti-forensic activity detected: Evidence of timestamp manipulation")
        print("=" * 70)

        return 2  # Exit code 2 = detection positive

    else:
        print("✓ " + "=" * 68)
        print("   No Timestamp Manipulation Detected")
        print("=" * 70)
        print()
        print("Analysis:")
        print(f"  Total triples: {total_triples:,}")
        print()
        print("Result:")
        print("  • All LNK target timestamps match MFT records")
        print("  • No evidence of timestamp manipulation")
        print("=" * 70)

        return 0  # Exit code 0 = no detection


if __name__ == '__main__':
    sys.exit(main())
