#!/usr/bin/env python3
"""
AF-TIMESTOMPING: Streaming MFT Filter
Extracts only MFT entries referenced by LNK files to enable in-memory detection.

Usage:
    python3 stream_filter_timestomp.py \
      --mft mft_filled_honest.jsonld \
      --lnk ../lnk-shortcut/lnk_filled_fixed.jsonld \
      --output-dir /tmp/timestomp/
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, Any, Set
from datetime import datetime


def extract_lnk_mft_refs(lnk_file: Path) -> Set[str]:
    """
    First pass: Extract all MFT entry numbers referenced by LNK files.

    Returns: Set of MFT entry numbers as strings
    """
    print(f"Pass 1: Extracting MFT references from LNK file...")
    print(f"  LNK file: {lnk_file.name} ({lnk_file.stat().st_size / (1024**2):.2f} MB)")

    mft_refs = set()
    lnk_count = 0

    with open(lnk_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

        # Handle both single object and array
        entries = data if isinstance(data, list) else [data]

        for entry in entries:
            # Look for WindowsLnkFacet with targetMftEntryNumber
            if '@graph' in entry:
                for item in entry['@graph']:
                    # Check if this is a File with facets
                    if item.get('@type') == 'observable:File' and 'core:hasFacet' in item:
                        facets = item['core:hasFacet']
                        if not isinstance(facets, list):
                            facets = [facets]

                        for facet in facets:
                            if isinstance(facet, dict):
                                facet_type = facet.get('@type', '')
                                # Check if it's a WindowsLnkFacet (can be string or list)
                                if 'WindowsLnkFacet' in str(facet_type):
                                    mft_entry = facet.get('dfc-ext:targetMftEntryNumber')
                                    if mft_entry:
                                        # Handle both dict format and direct value
                                        if isinstance(mft_entry, dict):
                                            mft_refs.add(str(mft_entry.get('@value', mft_entry)))
                                        else:
                                            mft_refs.add(str(mft_entry))
                                        lnk_count += 1

    print(f"  ✓ Found {lnk_count} LNK files referencing {len(mft_refs)} unique MFT entries")
    return mft_refs


def is_relevant_mft(entry: Dict[str, Any], mft_refs: Set[str]) -> bool:
    """
    Check if MFT entry is referenced by any LNK file.

    Needs:
    - MftFacet with entryNumber matching LNK references
    - MftFacet with created0x10 ($STANDARD_INFORMATION created time)
    - FileFacet with filePath
    """
    if '@graph' not in entry:
        return False

    for item in entry['@graph']:
        item_type = item.get('@type', '')

        # Check for MftFacet
        if item_type == 'dfc-ext:MftFacet':
            entry_num = item.get('dfc-ext:entryNumber')

            # Handle both dict format and direct value
            if isinstance(entry_num, dict):
                entry_num = str(entry_num.get('@value', ''))
            else:
                entry_num = str(entry_num) if entry_num else ''

            # Check if this entry number is referenced by LNK files
            if entry_num and entry_num in mft_refs:
                # Must also have created0x10 timestamp
                if 'dfc-ext:created0x10' in item:
                    return True

    return False


def filter_mft_stream(mft_file: Path, lnk_refs: Set[str], output_file: Path):
    """
    Second pass: Stream through MFT file and extract only referenced entries.
    """
    print(f"\nPass 2: Filtering MFT file...")
    print(f"  MFT file: {mft_file.name} ({mft_file.stat().st_size / (1024**2):.2f} MB)")
    print(f"  Looking for {len(lnk_refs)} referenced MFT entries")

    filtered_graph = []
    total = 0
    matched = 0
    context = None

    with open(mft_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

        # Extract context if present
        if isinstance(data, dict) and '@context' in data:
            context = data['@context']

        # Get the list of File entries from @graph
        if isinstance(data, dict) and '@graph' in data:
            entries = data['@graph']
        elif isinstance(data, list):
            entries = data
        else:
            entries = [data]

        # Filter entries that are Files with matching MFT entry numbers
        for item in entries:
            total += 1
            if item.get('@type') == 'observable:File' and 'core:hasFacet' in item:
                facets = item['core:hasFacet']
                if not isinstance(facets, list):
                    facets = [facets]

                # Check if any facet is MftFacet with matching entry number
                for facet in facets:
                    if isinstance(facet, dict):
                        facet_type = facet.get('@type', '')
                        # Check if facet_type contains 'MftFacet' (can be string or list)
                        if 'MftFacet' in str(facet_type):
                            entry_num = facet.get('dfc-ext:entryNumber')
                            if isinstance(entry_num, dict):
                                entry_num = str(entry_num.get('@value', ''))
                            else:
                                entry_num = str(entry_num) if entry_num else ''

                            if entry_num and entry_num in lnk_refs:
                                filtered_graph.append(item)
                                matched += 1
                                if matched % 10 == 0:
                                    print(f"  Progress: {matched} relevant entries found (scanned {total:,})", end='\r')
                                break  # Don't add same item twice

    print(f"\n  ✓ Filtered: {matched} relevant / {total:,} total entries")

    # Write filtered data
    output_data = {
        "@context": context,
        "@graph": filtered_graph
    } if context else filtered_graph

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)

    output_size = output_file.stat().st_size / (1024**2)
    input_size = mft_file.stat().st_size / (1024**2)
    reduction = (1 - output_size / input_size) * 100

    print(f"  ✓ Output: {output_file.name} ({output_size:.2f} MB)")
    print(f"  ✓ Reduction: {reduction:.1f}% ({input_size:.1f} MB → {output_size:.2f} MB)")

    return matched, total


def main():
    parser = argparse.ArgumentParser(
        description="AF-TIMESTOMPING: Extract MFT entries referenced by LNK files"
    )
    parser.add_argument('--mft', required=True, help="MFT JSON-LD file")
    parser.add_argument('--lnk', required=True, help="LNK JSON-LD file")
    parser.add_argument('--output-dir', required=True, help="Output directory")

    args = parser.parse_args()

    # Setup paths
    mft_file = Path(args.mft)
    lnk_file = Path(args.lnk)
    output_dir = Path(args.output_dir)

    # Validate inputs
    if not mft_file.exists():
        print(f"ERROR: MFT file not found: {mft_file}", file=sys.stderr)
        return 1

    if not lnk_file.exists():
        print(f"ERROR: LNK file not found: {lnk_file}", file=sys.stderr)
        return 1

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("AF-TIMESTOMPING: Streaming MFT Filter")
    print("=" * 70)
    print()

    start_time = datetime.now()

    # Pass 1: Extract LNK MFT references
    lnk_refs = extract_lnk_mft_refs(lnk_file)

    if not lnk_refs:
        print("\nWARNING: No MFT references found in LNK file!", file=sys.stderr)
        return 1

    # Pass 2: Filter MFT file
    mft_output = output_dir / "mft_lnk_filtered.jsonld"
    matched, total = filter_mft_stream(mft_file, lnk_refs, mft_output)

    # Copy LNK file (small enough)
    lnk_output = output_dir / "lnk_files.jsonld"
    print(f"\nCopying LNK file...")
    print(f"  ✓ {lnk_output.name} ({lnk_file.stat().st_size / (1024**2):.2f} MB)")

    import shutil
    shutil.copy2(lnk_file, lnk_output)

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
    print(f"  • {mft_output.name} - Filtered MFT entries")
    print(f"  • {lnk_output.name} - LNK shortcut files")
    print()
    print("Next step:")
    print(f"  python3 detect_timestomp_optimized.py {output_dir}")
    print("=" * 70)

    return 0


if __name__ == '__main__':
    sys.exit(main())
