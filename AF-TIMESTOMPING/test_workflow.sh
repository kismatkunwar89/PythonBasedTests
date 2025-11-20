#!/bin/bash
# AF-TIMESTOMPING Workflow Test

set -e  # Exit on error

echo "========================================"
echo "AF-TIMESTOMPING Workflow Test"
echo "========================================"
echo ""

MFT_FILE="mft_filled_honest.jsonld"
LNK_FILE="lnk_filled_fixed.jsonld"
OUTPUT_DIR="./stream_output"

echo "Test Configuration:"
echo "  MFT: $MFT_FILE"
echo "  LNK: $LNK_FILE"
echo "  Output: $OUTPUT_DIR"
echo ""

# Check files exist
if [ ! -f "$MFT_FILE" ]; then
    echo "ERROR: MFT file not found: $MFT_FILE"
    exit 1
fi

if [ ! -f "$LNK_FILE" ]; then
    echo "ERROR: LNK file not found: $LNK_FILE"
    exit 1
fi

# Step 1: Run streaming filter
echo "========================================"
echo "Step 1: Streaming MFT Filter"
echo "========================================"
echo ""

python3 stream_filter_timestomp.py \
    --mft "$MFT_FILE" \
    --lnk "$LNK_FILE" \
    --output-dir "$OUTPUT_DIR"

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

python3 detect_timestomp_optimized.py "$OUTPUT_DIR"

DETECTION_EXIT=$?

echo ""
echo "========================================"
echo "Test Results"
echo "========================================"
echo ""

if [ $DETECTION_EXIT -eq 2 ]; then
    echo "✓ AF-TIMESTOMPING Detection: TIMESTAMP MANIPULATION DETECTED"
    echo "  Exit code: 2 (positive detection)"
elif [ $DETECTION_EXIT -eq 0 ]; then
    echo "✓ AF-TIMESTOMPING Detection: No timestamp manipulation"
    echo "  Exit code: 0 (negative)"
else
    echo "✗ AF-TIMESTOMPING Detection: ERROR"
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
