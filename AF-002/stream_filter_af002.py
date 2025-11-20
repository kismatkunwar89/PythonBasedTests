#!/usr/bin/env python3
"""
AF-002: Streaming Filter for Selective Browser History Deletion Detection

Filters large MFT and USN files to extract only relevant entries:
- MFT: IndexedDB folder entries (contain domain names)
- USN: History file modifications (DataTruncation/DataOverwrite/DataExtend)
- History: All entries (already small)

Usage:
    python3 stream_filter_af002.py \
      --mft mft_filled_large.jsonld \
      --usn usn_filled_large.jsonld \
      --history history_filled.jsonld \
      --output-dir /tmp/af002_filtered/
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, Any, Set
from datetime import datetime


def filter_mft_indexeddb(mft_file: Path, output_file: Path):
    """
    Filter MFT to keep only IndexedDB folder entries.

    IndexedDB paths contain domain names like:
    .\\Users\\...\\IndexedDB\\https_www.youtube.com_0.indexeddb.leveldb
    """
    print(f"Pass 1: Filtering MFT for IndexedDB entries...")
    print(f"  MFT file: {mft_file.name} ({mft_file.stat().st_size / (1024**2):.2f} MB)")

    filtered_graph = []
    total = 0
    matched = 0
    context = None

    with open(mft_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

        # Extract context
        if isinstance(data, dict) and '@context' in data:
            context = data['@context']

        # Get entries
        if isinstance(data, dict) and '@graph' in data:
            entries = data['@graph']
        elif isinstance(data, list):
            entries = data
        else:
            entries = [data]

        # Filter for IndexedDB entries
        for item in entries:
            total += 1
            if item.get('@type') == 'observable:File' and 'core:hasFacet' in item:
                facets = item['core:hasFacet']
                if not isinstance(facets, list):
                    facets = [facets]

                # Check if any facet has IndexedDB in path
                for facet in facets:
                    if isinstance(facet, dict):
                        # Check FileFacet for filePath
                        if 'observable:filePath' in facet:
                            file_path = facet.get('observable:filePath', '')
                            if 'IndexedDB' in str(file_path):
                                filtered_graph.append(item)
                                matched += 1
                                if matched % 100 == 0:
                                    print(f"  Progress: {matched} IndexedDB entries found (scanned {total:,})", end='\r')
                                break
                        # Check MftFacet for parentPath
                        elif 'dfc-ext:parentPath' in facet:
                            parent_path = facet.get('dfc-ext:parentPath', '')
                            if 'IndexedDB' in str(parent_path):
                                filtered_graph.append(item)
                                matched += 1
                                if matched % 100 == 0:
                                    print(f"  Progress: {matched} IndexedDB entries found (scanned {total:,})", end='\r')
                                break

    print(f"\n  ✓ Filtered: {matched} IndexedDB entries / {total:,} total entries")

    # Write filtered data
    output_data = {
        "@context": context,
        "@graph": filtered_graph
    } if context else filtered_graph

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)

    output_size = output_file.stat().st_size / (1024**2)
    input_size = mft_file.stat().st_size / (1024**2)
    reduction = (1 - output_size / input_size) * 100 if input_size > 0 else 0

    print(f"  ✓ Output: {output_file.name} ({output_size:.2f} MB)")
    print(f"  ✓ Reduction: {reduction:.1f}% ({input_size:.1f} MB → {output_size:.2f} MB)")

    return matched, total


def filter_usn_history(usn_file: Path, output_file: Path):
    """
    Filter USN to keep only History file modifications.

    Looks for:
    - fileName contains "History"
    - updateReasons contains DataTruncation, DataOverwrite, or DataExtend
    """
    print(f"\nPass 2: Filtering USN for History file modifications...")
    print(f"  USN file: {usn_file.name} ({usn_file.stat().st_size / (1024**2):.2f} MB)")

    filtered_graph = []
    total = 0
    matched = 0
    context = None

    tampering_keywords = ['DataTruncation', 'DataOverwrite', 'DataExtend']

    with open(usn_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

        # Extract context
        if isinstance(data, dict) and '@context' in data:
            context = data['@context']

        # Get entries
        if isinstance(data, dict) and '@graph' in data:
            entries = data['@graph']
        elif isinstance(data, list):
            entries = data
        else:
            entries = [data]

        # Filter for History file modifications
        for item in entries:
            total += 1
            if item.get('@type') == 'observable:File' and 'core:hasFacet' in item:
                facets = item['core:hasFacet']
                if not isinstance(facets, list):
                    facets = [facets]

                has_history_filename = False
                has_tampering = False

                for facet in facets:
                    if isinstance(facet, dict):
                        # Check FileFacet for fileName
                        if 'observable:fileName' in facet:
                            file_name = str(facet.get('observable:fileName', ''))
                            if 'History' in file_name:
                                has_history_filename = True

                        # Check UsnFacet for updateReasons
                        if 'dfc-ext:updateReasons' in facet:
                            update_reasons = str(facet.get('dfc-ext:updateReasons', ''))
                            if any(keyword in update_reasons for keyword in tampering_keywords):
                                has_tampering = True

                # Keep if both conditions met
                if has_history_filename and has_tampering:
                    filtered_graph.append(item)
                    matched += 1
                    if matched % 100 == 0:
                        print(f"  Progress: {matched} History modifications found (scanned {total:,})", end='\r')

    print(f"\n  ✓ Filtered: {matched} History modifications / {total:,} total entries")

    # Write filtered data
    output_data = {
        "@context": context,
        "@graph": filtered_graph
    } if context else filtered_graph

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)

    output_size = output_file.stat().st_size / (1024**2)
    input_size = usn_file.stat().st_size / (1024**2)
    reduction = (1 - output_size / input_size) * 100 if input_size > 0 else 0

    print(f"  ✓ Output: {output_file.name} ({output_size:.2f} MB)")
    print(f"  ✓ Reduction: {reduction:.1f}% ({input_size:.1f} MB → {output_size:.2f} MB)")

    return matched, total


def main():
    parser = argparse.ArgumentParser(
        description="AF-002: Filter large MFT/USN files for browser history deletion detection"
    )
    parser.add_argument('--mft', required=True, help="MFT JSON-LD file")
    parser.add_argument('--usn', required=True, help="USN JSON-LD file")
    parser.add_argument('--history', required=True, help="History JSON-LD file")
    parser.add_argument('--output-dir', required=True, help="Output directory")

    args = parser.parse_args()

    # Setup paths
    mft_file = Path(args.mft)
    usn_file = Path(args.usn)
    history_file = Path(args.history)
    output_dir = Path(args.output_dir)

    # Validate inputs
    if not mft_file.exists():
        print(f"ERROR: MFT file not found: {mft_file}", file=sys.stderr)
        return 1

    if not usn_file.exists():
        print(f"ERROR: USN file not found: {usn_file}", file=sys.stderr)
        return 1

    if not history_file.exists():
        print(f"ERROR: History file not found: {history_file}", file=sys.stderr)
        return 1

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("AF-002: Streaming Filter for Browser History Deletion Detection")
    print("=" * 70)
    print()

    start_time = datetime.now()

    # Filter MFT for IndexedDB entries
    mft_output = output_dir / "mft_indexeddb_filtered.jsonld"
    mft_matched, mft_total = filter_mft_indexeddb(mft_file, mft_output)

    # Filter USN for History modifications
    usn_output = output_dir / "usn_history_filtered.jsonld"
    usn_matched, usn_total = filter_usn_history(usn_file, usn_output)

    # Copy History file (already small)
    history_output = output_dir / "history_all.jsonld"
    print(f"\nCopying History file...")
    print(f"  ✓ {history_output.name} ({history_file.stat().st_size / 1024:.2f} KB)")

    import shutil
    shutil.copy2(history_file, history_output)

    elapsed = (datetime.now() - start_time).total_seconds()

    print()
    print("=" * 70)
    print("Filtering Complete")
    print("=" * 70)
    print()
    print(f"Time: {elapsed:.1f}s")
    print(f"Output directory: {output_dir}")
    print()
    print("Files created:")
    print(f"  • {mft_output.name} - IndexedDB entries from MFT")
    print(f"  • {usn_output.name} - History file modifications from USN")
    print(f"  • {history_output.name} - Chrome History database")
    print()
    print("Next step:")
    print(f"  python3 detect_af002.py {mft_output} {history_output} {usn_output}")
    print("=" * 70)

    return 0


if __name__ == '__main__':
    sys.exit(main())
