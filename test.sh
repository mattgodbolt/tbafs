#!/bin/bash
# Test script for TBAFS extractor
# Extracts all sample archives, compares Blurp against reference, tests ADFS image creation
set -e

# Test Blurp extraction against known good reference
echo "Testing Blurp.b21 extraction against reference..."
rm -rf ./tmp/test_extract
mkdir -p ./tmp/test_extract
python3 tbafs.py extract samples/Blurp.b21 -o ./tmp/test_extract

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

FILE_COUNT=$(find ./tmp/test_extract -type f | wc -l)
echo "✓ Extracted $FILE_COUNT files"

# Test all other archives extract without error
echo ""
echo "Testing extraction of all sample archives..."
for archive in samples/*.b21; do
    name=$(basename "$archive" .b21)
    if [ "$name" = "Blurp" ]; then
        continue  # Already tested above
    fi
    rm -rf "./tmp/$name"
    if python3 tbafs.py extract "$archive" -o "./tmp/$name" > /dev/null 2>&1; then
        count=$(find "./tmp/$name" -type f | wc -l)
        echo "✓ $name.b21: extracted $count files"
    else
        echo "✗ $name.b21: extraction failed!"
        exit 1
    fi
done

# Test ADFS image creation
echo ""
echo "Testing ADFS image creation..."
rm -f ./tmp/test.adf
python3 tbafs.py extract samples/Blurp.b21 --adfs ./tmp/test.adf

# Verify ADFS image size (E format = 819200 bytes)
# Note: avoid stat as it can hang on stale NFS mounts
# Apply sed, as BSD 'wc' space-pads the count.
SIZE=$(wc -c < ./tmp/test.adf | sed -e 's/^ *//')
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
