#!/bin/bash
#
# AF-002: Complete Workflow - Selective Browser History Deletion Detection
#
# This script runs the complete AF-002 detection workflow:
# 1. Generate large MFT and USN JSON-LD files from CSV (if needed)
# 2. Filter large files down to relevant entries
# 3. Run detection on filtered data
#

set -e  # Exit on error

echo "======================================================================"
echo "AF-002: Selective Browser History Deletion Detection - Full Workflow"
echo "======================================================================"
echo

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MFT_CSV="../baseline/20250729004651_MFTECmd_\$MFT_Output.csv"
USN_CSV="../USN/USNCASE2all.csv"
HISTORY_FILE="history_case2.jsonld"

MFT_LARGE="mft_case2.jsonld"
USN_LARGE="usn_case2.jsonld"

OUTPUT_DIR="./stream_output"

# Step 0: Check if large files exist, generate if needed
echo "======================================================================"
echo "Step 0: Checking/Generating Large JSON-LD Files"
echo "======================================================================"
echo

if [ ! -f "$MFT_LARGE" ]; then
    echo "→ Generating MFT JSON-LD from CSV..."
    cd ../baseline
    python3 mft_template_filler.py "20250729004651_MFTECmd_\$MFT_Output.csv" "../AF-002/mft_filled_large.jsonld"
    cd "$SCRIPT_DIR"
    echo "✓ MFT file generated"
else
    echo "✓ MFT file already exists: $MFT_LARGE"
    ls -lh "$MFT_LARGE"
fi

echo

if [ ! -f "$USN_LARGE" ]; then
    echo "→ Generating USN JSON-LD from CSV..."
    cd ../USN
    python3 usn_template_filler.py "USNCASE2all.csv" "../AF-002/$USN_LARGE"
    cd "$SCRIPT_DIR"
    echo "✓ USN file generated"
else
    echo "✓ USN file already exists: $USN_LARGE"
    ls -lh "$USN_LARGE"
fi

echo

# Step 1: Filter large files
echo "======================================================================"
echo "Step 1: Streaming Filter (2.3 GB → KB)"
echo "======================================================================"
echo

python3 stream_filter_af002.py \
    --mft "$MFT_LARGE" \
    --usn "$USN_LARGE" \
    --history "$HISTORY_FILE" \
    --output-dir "$OUTPUT_DIR"

echo

# Step 2: Run detection
echo "======================================================================"
echo "Step 2: Running AF-002 Detection"
echo "======================================================================"
echo

python3 detect_af002.py \
    "$OUTPUT_DIR/mft_indexeddb_filtered.jsonld" \
    "$OUTPUT_DIR/history_all.jsonld" \
    "$OUTPUT_DIR/usn_history_filtered.jsonld"

echo
echo "======================================================================"
echo "Workflow Complete!"
echo "======================================================================"
echo
echo "Summary:"
echo "  1. Large files: MFT (1.7 GB) + USN (569 MB) + History (13 KB)"
echo "  2. Filtered data: ~0.11 MB total (99.99% reduction)"
echo "  3. Detection completed on filtered data"
echo
echo "Filtered files are in: $OUTPUT_DIR"
echo "======================================================================"
