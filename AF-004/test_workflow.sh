#!/bin/bash
# Quick test of the AF-004 optimized workflow

set -e  # Exit on error

echo "========================================"
echo "AF-004 Workflow Test"
echo "========================================"
echo ""

# Test with Case5 data (1.5GB MFT + 467MB USN)
MFT_FILE="mft_filled_case4.jsonld"
USN_FILE="usn_filled_case4.jsonld"
OUTPUT_DIR="./stream_output"

echo "Test Configuration:"
echo "  MFT: $MFT_FILE"
echo "  USN: $USN_FILE"
echo "  Output: $OUTPUT_DIR"
echo ""

# Check files exist
if [ ! -f "$MFT_FILE" ]; then
    echo "ERROR: MFT file not found: $MFT_FILE"
    exit 1
fi

if [ ! -f "$USN_FILE" ]; then
    echo "ERROR: USN file not found: $USN_FILE"
    exit 1
fi

# Step 1: Run streaming filter
echo "========================================"
echo "Step 1: Streaming VSS Filter"
echo "========================================"
echo ""

python3 stream_filter_vss.py \
    --mft "$MFT_FILE" \
    --usn "$USN_FILE" \
    --output-dir "$OUTPUT_DIR" \
    --output-format json-ld

if [ $? -ne 0 ]; then
    echo "ERROR: Filtering failed"
    exit 1
fi

echo ""

# Step 2: Run detection on filtered data
echo "========================================"
echo "Step 2: Detection on Filtered Data"
echo "========================================"
echo ""

python3 detect_af004_optimized.py \
    "$OUTPUT_DIR/mft_vss_filtered.jsonld" \
    "$OUTPUT_DIR/usn_vss_filtered.jsonld" \
    --verbose

DETECTION_EXIT=$?

echo ""
echo "========================================"
echo "Test Results"
echo "========================================"
echo ""

if [ $DETECTION_EXIT -eq 2 ]; then
    echo "✓ AF-004 Detection: VSS PURGE DETECTED"
    echo "  Exit code: 2 (positive detection)"
elif [ $DETECTION_EXIT -eq 0 ]; then
    echo "✓ AF-004 Detection: No VSS purge"
    echo "  Exit code: 0 (negative)"
else
    echo "✗ AF-004 Detection: ERROR"
    echo "  Exit code: $DETECTION_EXIT"
    exit $DETECTION_EXIT
fi

echo ""
echo "Filtered files available at:"
echo "  $OUTPUT_DIR"
echo ""
echo "To cleanup: rm -rf $OUTPUT_DIR"
echo ""
echo "========================================"
echo "TEST COMPLETED SUCCESSFULLY"
echo "========================================"

exit 0
