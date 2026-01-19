#!/bin/bash
# Test script for TBAFS extractor
# Extracts sample, creates reproducible tarball, verifies MD5
set -e

rm -rf ./tmp/test_extract
mkdir -p ./tmp/test_extract
python3 tbafs.py extract samples/Blurp.b21 -o ./tmp/test_extract

# Create reproducible tarball (sorted, fixed mtime, no owner info)
HASH=$(tar --sort=name --mtime='2020-01-01 00:00:00' --owner=0 --group=0 \
    -cf - -C ./tmp/test_extract . | md5sum | cut -d' ' -f1)

EXPECTED="d8715fdeb8897575e92a94d1c14cb0f1"

if [ "$HASH" = "$EXPECTED" ]; then
    echo "✓ MD5 matches: $HASH"
    exit 0
else
    echo "✗ MD5 mismatch!"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $HASH"
    exit 1
fi
