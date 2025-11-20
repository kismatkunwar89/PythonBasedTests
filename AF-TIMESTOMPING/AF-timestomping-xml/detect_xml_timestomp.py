#!/usr/bin/env python3
"""
AF-TIMESTOMPING-XML: Office Document Timestamp Manipulation Detection

Detects timestamp manipulation by comparing Office XML internal metadata
(dcterms:created from docProps/core.xml) with MFT $STANDARD_INFORMATION timestamps.

Office documents (docx, xlsx, pptx) embed creation timestamps in internal XML
metadata that persist even when filesystem timestamps are manipulated.

Usage:
    python3 detect_xml_timestomp.py <office_xml_file.jsonld>
    python3 detect_xml_timestomp.py --file office_xml_filled.jsonld --rule rule_xml_timestomp.rq
"""

import sys
import argparse
from pathlib import Path
from rdflib import Dataset
from datetime import datetime


def parse_args():
    parser = argparse.ArgumentParser(
        description="AF-TIMESTOMPING-XML: Office document timestamp manipulation detection"
    )
    parser.add_argument(
        'file',
        nargs='?',
        help="Office XML metadata JSON-LD file"
    )
    parser.add_argument(
        '--file',
        dest='file_path',
        help="Office XML metadata JSON-LD file (alternative)"
    )
    parser.add_argument(
        '--rule',
        default='rule_xml_timestomp.rq',
        help="SPARQL rule file (default: rule_xml_timestomp.rq)"
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help="Show detailed loading information"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    # Determine file path
    data_file = Path(args.file) if args.file else (Path(args.file_path) if args.file_path else None)

    # Validation
    if not data_file or not data_file.exists():
        print(f"ERROR: Data file not found: {data_file}", file=sys.stderr)
        print("\nUsage: python3 detect_xml_timestomp.py <office_xml_file.jsonld>", file=sys.stderr)
        return 1

    rule_file = Path(args.rule)
    if not rule_file.exists():
        # Try relative to script directory
        script_dir = Path(__file__).parent
        rule_file = script_dir / args.rule
        if not rule_file.exists():
            print(f"ERROR: Rule file not found: {args.rule}", file=sys.stderr)
            return 1

    print("=" * 70)
    print("AF-TIMESTOMPING-XML: Office Document Timestamp Manipulation Detection")
    print("=" * 70)
    print()
    print(f"Data File: {data_file.name}")
    print(f"  Size: {data_file.stat().st_size / 1024:.2f} KB")
    print()
    print(f"Rule: {rule_file.name}")
    print()

    # Load SPARQL query
    query = rule_file.read_text()

    # Create dataset
    print("=" * 70)
    print("Loading Office XML Metadata")
    print("=" * 70)
    print()

    ds = Dataset()

    print(f"Loading data from {data_file.name}...")
    ds.parse(data_file, format='json-ld')
    print(f"  ✓ Loaded")

    total_triples = len(ds)
    print(f"\n  Total triples: {total_triples:,}")
    print()

    # Execute query
    print("=" * 70)
    print("Running AF-TIMESTOMPING-XML Detection Query")
    print("=" * 70)
    print()

    if args.verbose:
        print("Executing SPARQL query...")

    results = list(ds.query(query))

    # Analyze results
    print()
    if results:
        print("🚨 " + "=" * 68)
        print("   AF-TIMESTOMPING-XML ALERT: Timestamp Manipulation Detected!")
        print("=" * 70)
        print()
        print(f"Found {len(results)} timestomping instance(s):")
        print()

        timestomp_count = 0

        for i, row in enumerate(results, 1):
            # Extract variables from SPARQL result
            file_path = str(row.filePath) if hasattr(row, 'filePath') else "Unknown"
            xml_created_str = str(row.xmlCreated) if hasattr(row, 'xmlCreated') else ""
            mft_si_str = str(row.mftSiCreated) if hasattr(row, 'mftSiCreated') else ""
            mft_fn_str = str(row.mftFnCreated) if hasattr(row, 'mftFnCreated') else ""

            # Parse timestamps using datetime (no isodate needed for ISO format)
            try:
                from datetime import datetime as dt
                xml_dt = dt.fromisoformat(xml_created_str.replace('Z', '+00:00'))
                si_dt = dt.fromisoformat(mft_si_str.replace('Z', '+00:00'))
                fn_dt = dt.fromisoformat(mft_fn_str.replace('Z', '+00:00'))

                # Calculate differences
                xml_vs_si_diff = abs((xml_dt - si_dt).total_seconds())
                si_fn_diff = abs((si_dt - fn_dt).total_seconds())

                # CRITICAL FILTER: Only flag if $SI and $FN differ by > 60 seconds
                # This confirms $STANDARD_INFORMATION was manipulated, not just filesystem events
                if si_fn_diff <= 60:
                    continue

                timestomp_count += 1

                print(f"{timestomp_count}. Timestamp Manipulation Detected")
                print(f"   Office Document: {file_path}")
                print()
                print(f"   Timestamps:")
                print(f"     Office XML Created (dcterms:created): {xml_created_str}")
                print(f"     MFT $SI Created:                      {mft_si_str}")
                print(f"     MFT $FN Created:                      {mft_fn_str}")
                print()
                print(f"   🚨 EVIDENCE:")
                print(f"     • Office XML metadata shows original creation: {xml_created_str}")
                print(f"     • MFT $SI timestamp was changed {xml_vs_si_diff:.1f} seconds later")
                print(f"     • $SI differs from $FN by {si_fn_diff:.1f} seconds")
                print(f"     • This indicates $STANDARD_INFORMATION was tampered")
                print()
            except Exception as e:
                print(f"Error parsing dates for {file_path}: {e}")
                continue

        if timestomp_count > 0:
            print("CONCLUSION:")
            print("  ✓ Office XML metadata preserves original creation timestamps")
            print("  ✓ MFT $STANDARD_INFORMATION shows modified timestamps")
            print("  ✓ MFT $FILE_NAME differs significantly from $SI")
            print()
            print("  → Anti-forensic activity detected: Timestamp manipulation via timestomp tool")
            print("=" * 70)

            return 2  # Exit code 2 = detection positive
        else:
            print("NOTE: SPARQL found matches but $SI/$FN difference < 60s")
            print("This may indicate normal filesystem operations, not timestomping.")
            print("=" * 70)
            return 0

    else:
        print("✓ " + "=" * 68)
        print("   No Timestamp Manipulation Detected")
        print("=" * 70)
        print()
        print("Analysis:")
        print(f"  Total triples: {total_triples:,}")
        print()
        print("Result:")
        print("  • Office XML metadata matches MFT timestamps")
        print("  • No evidence of timestamp manipulation")
        print("=" * 70)

        return 0  # Exit code 0 = no detection


if __name__ == '__main__':
    sys.exit(main())
