#!/bin/bash
# AF-007 Workflow Test

set -e  # Exit on error

echo "========================================"
echo "AF-007 Workflow Test"
echo "========================================"
echo ""

USN_FILE="usn_filled_case7.jsonld"
SECURITY_FILE="security_evtx_case7.jsonld"
SYSTEM_FILE="system_evtx_case7.jsonld"
OUTPUT_DIR="./stream_output"

echo "Test Configuration:"
echo "  USN: $USN_FILE"
echo "  Security: $SECURITY_FILE"
echo "  System: $SYSTEM_FILE"
echo "  Output: $OUTPUT_DIR"
echo ""

# Check files exist
if [ ! -f "$USN_FILE" ]; then
    echo "ERROR: USN file not found: $USN_FILE"
    exit 1
fi

if [ ! -f "$SECURITY_FILE" ]; then
    echo "ERROR: Security file not found: $SECURITY_FILE"
    exit 1
fi

if [ ! -f "$SYSTEM_FILE" ]; then
    echo "ERROR: System file not found: $SYSTEM_FILE"
    exit 1
fi

# Step 1: Run streaming filter
echo "========================================"
echo "Step 1: Streaming Event Log Filter"
echo "========================================"
echo ""

if [ -f "$OUTPUT_DIR/security_1102_filtered.jsonld" ] && [ -f "$OUTPUT_DIR/system_events.jsonld" ] && [ -f "$OUTPUT_DIR/usn_security_filtered.jsonld" ]; then
    echo "Filtered files already exist in $OUTPUT_DIR. Skipping filter step."
else
    python3 stream_filter_evtx.py \
        --usn "$USN_FILE" \
        --security "$SECURITY_FILE" \
        --system "$SYSTEM_FILE" \
        --output-dir "$OUTPUT_DIR"

    if [ $? -ne 0 ]; then
        echo "ERROR: Filtering failed"
        exit 1
    fi
fi

echo ""

# Step 2: Run detection on filtered data
echo "========================================"
echo "Step 2: Detection on Filtered Data"
echo "========================================"
echo ""

python3 detect_af007_optimized.py "$OUTPUT_DIR"

DETECTION_EXIT=$?

echo ""
echo "========================================"
echo "Test Results"
echo "========================================"
echo ""

if [ $DETECTION_EXIT -eq 2 ]; then
    echo "✓ AF-007 Detection: LOG CLEARING DETECTED"
    echo "  Exit code: 2 (positive detection)"
elif [ $DETECTION_EXIT -eq 0 ]; then
    echo "✓ AF-007 Detection: No log clearing"
    echo "  Exit code: 0 (negative)"
else
    echo "✗ AF-007 Detection: ERROR"
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
