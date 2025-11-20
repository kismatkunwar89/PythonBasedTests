#!/usr/bin/env python3
"""
AF-007: Event Log Clearing Detection (Optimized for Filtered Data)

Works with pre-filtered event log data from stream_filter_evtx.py
Supports filtered or original data.

Usage:
    # Option 1: Filter first, then detect (recommended for large files)
    python3 stream_filter_evtx.py --usn X --security Y --output-dir /tmp/evtx/
    python3 detect_af007_optimized.py /tmp/evtx/

    # Option 2: Direct detection on small files
    python3 detect_af007_optimized.py --usn small_usn.jsonld --security small_security.jsonld

    # Option 3: Specify files individually
    python3 detect_af007_optimized.py \
      --usn /tmp/evtx/usn_security_filtered.jsonld \
      --security /tmp/evtx/security_1102_filtered.jsonld \
      --system /tmp/evtx/system_events.jsonld
"""

import sys
import argparse
from pathlib import Path
from rdflib import Dataset
from datetime import datetime


def parse_args():
    parser = argparse.ArgumentParser(
        description="AF-007 Event Log Clearing Detection (optimized for filtered data)"
    )

    # Accept either a directory or individual files
    parser.add_argument(
        'filter_dir',
        nargs='?',
        help="Directory containing filtered files (from stream_filter_evtx.py)"
    )
    parser.add_argument(
        '--usn',
        help="Path to USN file (JSON-LD)"
    )
    parser.add_argument(
        '--security',
        help="Path to Security event log file (JSON-LD)"
    )
    parser.add_argument(
        '--system',
        help="Path to System event log file (JSON-LD, optional)"
    )
    parser.add_argument(
        '--rule-file',
        default='RULE.rq',
        help="SPARQL rule file (default: RULE.rq)"
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
        usn_file = filter_dir / "usn_security_filtered.jsonld"
        security_file = filter_dir / "security_1102_filtered.jsonld"
        system_file = filter_dir / "system_events.jsonld"
    else:
        usn_file = Path(args.usn) if args.usn else None
        security_file = Path(args.security) if args.security else None
        system_file = Path(args.system) if args.system else None

    # Validation
    if not usn_file or not usn_file.exists():
        print(f"ERROR: USN file not found: {usn_file}", file=sys.stderr)
        return 1

    if not security_file or not security_file.exists():
        print(f"ERROR: Security file not found: {security_file}", file=sys.stderr)
        return 1

    rule_file = Path(args.rule_file)
    if not rule_file.exists():
        print(f"ERROR: Rule file not found: {rule_file}", file=sys.stderr)
        print(f"  Looking in current directory: {Path.cwd()}", file=sys.stderr)
        return 1

    print("=" * 70)
    print("AF-007: Event Log Clearing Detection (Optimized)")
    print("=" * 70)
    print()
    print(f"USN File: {usn_file.name}")
    print(f"  Size: {usn_file.stat().st_size / (1024**2):.2f} MB")
    print()
    print(f"Security File: {security_file.name}")
    print(f"  Size: {security_file.stat().st_size / (1024**2):.2f} MB")
    print()
    if system_file and system_file.exists():
        print(f"System File: {system_file.name}")
        print(f"  Size: {system_file.stat().st_size / (1024**2):.2f} MB")
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

    # Load USN data
    print(f"Loading USN data from {usn_file.name}...")
    ds.parse(usn_file, format='json-ld')
    print(f"  ✓ Loaded")

    # Load Security event log
    print(f"Loading Security event log from {security_file.name}...")
    ds.parse(security_file, format='json-ld')
    print(f"  ✓ Loaded")

    # Load System event log if provided
    if system_file and system_file.exists():
        print(f"Loading System event log from {system_file.name}...")
        ds.parse(system_file, format='json-ld')
        print(f"  ✓ Loaded")

    total_triples = len(ds)
    print(f"\n  Total triples: {total_triples:,}")
    print()

    # Execute query
    print("=" * 70)
    print("Running AF-007 Detection Query")
    print("=" * 70)
    print()

    if args.verbose:
        print("Executing SPARQL query...")

    results = list(ds.query(query))

    # Analyze results
    print()
    if results:
        # Categorize events
        event_1102 = None
        usn_truncations = []

        for row in results:
            event_type = str(row.event_type) if row.event_type else ""
            time = str(row.time) if row.time else ""

            if "Event 1102" in event_type:
                event_1102 = {'time': time, 'row': row}
            elif "USN DataTruncation" in event_type:
                usn_truncations.append({'time': time, 'row': row})

        # Check for contradiction
        contradiction_detected = False
        if event_1102 and usn_truncations:
            clear_time = datetime.fromisoformat(
                event_1102['time'].replace('Z', '+00:00'))

            for usn in usn_truncations:
                usn_time = datetime.fromisoformat(
                    usn['time'].replace('Z', '+00:00'))
                if usn_time < clear_time:
                    contradiction_detected = True
                    break

        # Display results
        if contradiction_detected:
            print("🚨 " + "=" * 68)
            print("   AF-007 ALERT: Event Log Clearing Detected!")
            print("=" * 70)
            print()
            print(f"Found {len(results)} event(s):")
            print()

            # Show Event 1102
            if event_1102:
                print(f"Event 1102 (Log Cleared):")
                print(f"  Timestamp: {event_1102['time']}")
                print(f"  Details: {event_1102['row'].details}")
                print()

            # Show USN truncations
            print(f"USN Truncations ({len(usn_truncations)}):")
            for i, usn in enumerate(usn_truncations, 1):
                time_diff = (clear_time - datetime.fromisoformat(usn['time'].replace('Z', '+00:00'))).total_seconds()
                print(f"  {i}. {usn['time']} ({time_diff:.1f}s before Event 1102)")
                print(f"     {usn['row'].details}")
            print()

            print("=" * 70)
            print("CONCLUSION:")
            print("  ✓ Event 1102 (log cleared) found in Security log")
            print("  ✓ USN Journal shows Security.evtx truncation BEFORE Event 1102")
            print()
            print("  → Anti-forensic activity detected: Evidence of log tampering")
            print("=" * 70)

            return 2  # Exit code 2 = detection positive

        else:
            print("ℹ️  " + "=" * 67)
            print("   Events Found (No Contradiction)")
            print("=" * 70)
            print()
            print(f"Found {len(results)} event(s):")
            print()

            for i, row in enumerate(results, 1):
                event_type = str(row.event_type) if row.event_type else ""
                time = str(row.time) if row.time else ""
                details = str(row.details) if row.details else ""

                print(f"{i}. [{time}] {event_type}")
                print(f"   {details}")
                print()

            print("=" * 70)
            print("No anti-forensic contradiction detected.")
            print("=" * 70)

            return 0

    else:
        print("✓ " + "=" * 68)
        print("   No Event 1102 or USN Truncations Found")
        print("=" * 70)
        print()
        print("Analysis:")
        print(f"  Total triples: {total_triples:,}")
        print()
        print("Possible reasons:")
        print("  • No event log clearing occurred")
        print("  • Event 1102 not present in Security log")
        print("  • No USN truncation operations on Security.evtx")
        print("=" * 70)

        return 0  # Exit code 0 = no detection


if __name__ == '__main__':
    sys.exit(main())
