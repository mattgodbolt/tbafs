#!/bin/bash
# Test script for TBAFS extractor
# Extracts sample, compares against reference files, tests ADFS image creation
set -e

rm -rf ./tmp/test_extract
mkdir -p ./tmp/test_extract
python3 tbafs.py extract samples/Blurp.b21 -o ./tmp/test_extract

# Compare extracted files with reference
echo ""
echo "Comparing extracted files with reference..."
DIFF_OUTPUT=$(diff -rq ./tmp/test_extract ./comparison/Blurp 2>&1)
if [ -z "$DIFF_OUTPUT" ]; then
    echo "✓ All extracted files match reference"
else
    echo "✗ Extraction mismatch!"
    echo "$DIFF_OUTPUT"
    exit 1
fi

# Count files
FILE_COUNT=$(find ./tmp/test_extract -type f | wc -l)
echo "✓ Extracted $FILE_COUNT files"

# Test ADFS image creation
echo ""
echo "Testing ADFS image creation..."
rm -f ./tmp/test.adf
python3 tbafs.py extract samples/Blurp.b21 --adfs ./tmp/test.adf

# Verify ADFS image size (E format = 819200 bytes)
SIZE=$(stat -c%s ./tmp/test.adf 2>/dev/null || stat -f%z ./tmp/test.adf)
if [ "$SIZE" = "819200" ]; then
    echo "✓ ADFS image size correct: $SIZE bytes"
else
    echo "✗ ADFS image size incorrect!"
    echo "  Expected: 819200"
    echo "  Got:      $SIZE"
    exit 1
fi

# Verify ADFS has valid NewDir signature at root
# E format: root at 0x800, Nick at bytes 1-4 and tail+0x24 (0xFFB)
NICK_START=$(xxd -s $((0x800 + 1)) -l 4 -p ./tmp/test.adf)
NICK_END=$(xxd -s $((0xFFB)) -l 4 -p ./tmp/test.adf)
if [ "$NICK_START" = "4e69636b" ] && [ "$NICK_END" = "4e69636b" ]; then
    echo "✓ ADFS root directory has valid 'Nick' signatures"
else
    echo "✗ ADFS root directory missing 'Nick' signature"
    echo "  Start (0x801): $NICK_START"
    echo "  End (0xFFB):   $NICK_END"
    exit 1
fi

echo ""
echo "All tests passed!"
