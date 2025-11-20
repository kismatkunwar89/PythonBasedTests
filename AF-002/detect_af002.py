#!/usr/bin/env python3
"""
AF-002: Selective Browser History Deletion Detection
Uses RULE.rq to detect contradictions between IndexedDB and Chrome History

Usage:
    python3 detect_af002.py <mft_file> <history_file> <usn_file>

Example:
    python3 detect_af002.py ../baseline/mft_filled_case2.jsonld ../HISTORY_DB/history_filled.jsonld ../USN/usn_filled_case2.jsonld
"""

import sys
from rdflib import Dataset

# Check arguments
if len(sys.argv) != 4:
    print("Usage: python3 detect_af002.py <mft_file> <history_file> <usn_file>")
    print("\nExample:")
    print("  python3 detect_af002.py ../baseline/mft_filled_case2.jsonld ../HISTORY_DB/history_filled.jsonld ../USN/usn_filled_case2.jsonld")
    sys.exit(1)

mft_file = sys.argv[1]
history_file = sys.argv[2]
usn_file = sys.argv[3]

# Load RULE.rq
with open("RULE.rq", "r") as f:
    query = f.read()

# Create dataset with named graphs
ds = Dataset()

# Load MFT graph (IndexedDB folder structure)
print(f"Loading MFT graph from: {mft_file}")
mft_graph = ds.graph("urn:graph:mft")
mft_graph.parse(mft_file, format="json-ld")
print(f"  {len(mft_graph)} triples loaded")

# Load History graph (Chrome History database)
print(f"Loading History graph from: {history_file}")
history_graph = ds.graph("urn:graph:history")
history_graph.parse(history_file, format="json-ld")
print(f"  {len(history_graph)} triples loaded")

# Load USN graph (file system evidence)
print(f"Loading USN graph from: {usn_file}")
usn_graph = ds.graph("urn:graph:usn")
usn_graph.parse(usn_file, format="json-ld")
print(f"  {len(usn_graph)} triples loaded")

# Execute RULE.rq
print("\n" + "="*60)
print("Running AF-002 Detection Query (RULE.rq)")
print("="*60 + "\n")

results = list(ds.query(query))

if results:
    print(f"🚨 AF-002 ALERT: Selective Browser History Deletion Detected!")
    print(f"\nFound {len(results)} contradiction(s):\n")

    for i, row in enumerate(results, 1):
        print(f"Contradiction #{i}:")
        print(f"  Domain:       {row.domain}")
        print(f"  MFT File:     {row.mft_file}")
        print(f"  USN Evidence: {row.usn_evidence}")
        print()

    print("="*60)
    print("CONCLUSION: Domain exists in IndexedDB folders (MFT)")
    print("            BUT missing from Chrome History database")
    print("            AND USN Journal shows History file modification")
    print("="*60)
else:
    print("✓ No selective deletion detected")
    print("  All IndexedDB domains found in Chrome History")
    print("  OR no USN tampering evidence")
