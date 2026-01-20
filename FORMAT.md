# TBAFS File Format Specification

This document describes the TBAFS archive format, a proprietary format created by TBA Software for RISC OS computers. This specification was reverse-engineered from sample archives and validated against disassembly of the TBAFSModR RISC OS module.

## Overview

TBAFS (TBA Filing System) is a high-performance archive format featuring:
- LZW compression (12-bit, compatible with Unix `compress`)
- RISC OS metadata preservation (filetypes, timestamps)
- Hierarchical directory structure
- Large file support via multi-block storage

## File Structure

```
+------------------+
|     Header       |  (32+ bytes)
+------------------+
| Root Dir Block   |  (variable)
+------------------+
|   Dir Entries    |  (64 bytes each)
+------------------+
|   Data Blocks    |  (variable, interleaved)
+------------------+
| More Entries...  |  (subdirectory entries follow data)
+------------------+
```

## Archive Header

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | Magic number: `TAFS` (0x53464154 LE) |
| 0x04 | 4 | Version/constant: must be 0xC8 (200) |
| 0x08 | 4 | Unknown constant: 0x10 (16) |
| 0x0C | 4 | Directory header size: 0x90 (144) |
| 0x10 | 4 | Reserved (zero) |
| 0x14 | 4 | Reserved (zero) |
| 0x18 | 4 | **Root entry table position** (e.g., 0x114) |
| 0x1C | 4 | Entry count in root directory |

Note: The module validates bytes 4-7 == 0xC8 as a version check. The entry table position at header[0x18] is loaded by the module at 0x1c8-0x1cc.

## Directory Entry (64 bytes)

Each file or directory is described by a 64-byte entry:

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | **Entry type**: 1=file, 2=directory, 0xFFFFFFFF=end marker |
| 0x04 | 4 | RISC OS load address |
| 0x08 | 4 | RISC OS exec address |
| 0x0C | 4 | Uncompressed file size (0 for directories) |
| 0x10 | 4 | RISC OS file attributes |
| 0x14 | 20 | **Filename** (null-terminated, up to 19 chars + NUL) |
| 0x28 | 20 | Reserved/unknown fields |
| 0x3c | 4 | **Data block position** (absolute file offset to block header) |

**Note on compression**: The compression type is NOT stored in the directory entry. It is encoded in the **data block header** (h0 high byte). The module reads the data position from entry[0x3c] (code at 0x1fac: `ldr r0, [ip, 0x60c]`).

### Entry Type Values

| Value | Meaning |
|-------|---------|
| 0x00000001 | File |
| 0x00000002 | Directory |
| 0xFFFFFFFF | End marker (no more entries in this block) |

### RISC OS Load Address

The load address encodes the filetype when bits 20-31 are 0xFFF:
```
0xFFFttthh
     ^^^
     filetype (12 bits)
```

Common filetypes:
- 0xFFF = Text
- 0xFFE = Command (Obey)
- 0xFFD = Data
- 0xFF9 = Sprite
- 0xFF8 = Absolute (executable)
- 0xFFA = Module
- 0xFEB = Obey (script)

## Data Storage Formats

TBAFS supports multiple storage formats, identified by a **compression type** encoded in h0.

### Compression Types

The **high byte of h0** indicates the compression type:

| Type | h0 Pattern | Description |
|------|------------|-------------|
| 0 | `0x00xxxxxx` | Raw/uncompressed data |
| 1 | `0x01xxxxxx` | HCT1 compressed (Huffman) - **speculative, untested** |
| 2 | `0x02xxxxxx` | Squash compressed (LZW) |

### Type 2: Squash Compressed Block (8-byte header)

For compressed blocks (h0 high byte = 0x02):

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | h0: `(0x02 << 24) \| uncompressed_size` |
| 0x04 | 4 | h1: Compressed data size in bytes |
| 0x08 | N | LZW data (starts with magic `1F 9D 8C`) |

Example: `h0 = 0x02000113` → type=2 (compressed), uncompressed_size=275

### Type 0: Raw/Uncompressed Block (4-byte header)

For uncompressed blocks (h0 high byte = 0x00):

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | h0: Uncompressed size (type=0, so high byte is 0) |
| 0x04 | N | Raw file data |

Example: `h0 = 0x00000ccd` → type=0 (raw), size=3277 bytes

**Important**: Raw blocks have only a 4-byte header, with data starting at +4, NOT +8.

### Type 1: HCT1 Compressed Block (8-byte header) - SPECULATIVE

> **Warning**: This section is derived from disassembly analysis only. No archives using Type 1 compression have been found for testing. Treat this documentation as speculative until verified against real data.

For HCT1 compressed blocks (h0 high byte = 0x01):

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | h0: `(0x01 << 24) \| uncompressed_size` |
| 0x04 | 4 | h1: Compressed data size in bytes |
| 0x08 | N | HCT1 compressed data |

**HCT1 Format Details** (from disassembly at 0xefc-0x1700):

- Internal magic signature: "HCT1" (0x31544348 little-endian) at module offset 0xf10
- Huffman-based compression algorithm
- Decompression implemented entirely within the TBAFSModR module (no external SWI calls)

**Decompression stages** (traced from disassembly):

1. **Initialization** (0x14d0): Set up decode state
2. **Frequency counting** (0xfb0-0x1150): Build 256-entry byte histogram from compressed data
3. **Huffman tree construction** (0x1264-0x1488): Build canonical Huffman decode tables
4. **Bitstream decoding** (0x1678+): Traverse Huffman tree bit-by-bit to emit output bytes

**Key observations**:
- Uses canonical Huffman coding (code lengths stored, not explicit tree)
- 256-symbol alphabet (one per byte value)
- Tree traversal at 0x15e4 uses `lsrs r2, r2, 1` for bit extraction
- Decode tables stored in module workspace

**Why HCT1 might exist**: Huffman compression is faster to decompress than LZW but typically achieves lower compression ratios. HCT1 may have been used for files where decompression speed was prioritized over archive size.

### Detecting Storage Format

```python
h0 = read_u32(block_header)
compression_type = (h0 >> 24) & 0xFF
uncomp_size = h0 & 0xFFFFFF

if compression_type == 2:
    # Squash compressed: 8-byte header, h1 = compressed size
    comp_size = read_u32(block_header + 4)
    lzw_data = data[block_header + 8 : block_header + 8 + comp_size]
elif compression_type == 1:
    # HCT1 compressed: 8-byte header, h1 = compressed size (SPECULATIVE)
    comp_size = read_u32(block_header + 4)
    hct1_data = data[block_header + 8 : block_header + 8 + comp_size]
    # Requires HCT1 Huffman decompressor - not yet implemented
elif compression_type == 0:
    # Raw: 4-byte header, data starts at +4
    raw_data = data[block_header + 4 : block_header + 4 + uncomp_size]
```

## Compression Format

TBAFS uses the RISC OS "Squash" compression, which is:
- 12-bit LZW (Lempel-Ziv-Welch)
- Compatible with Unix `compress -b 12`
- Magic bytes: `1F 9D 8C`
  - `1F 9D` = Unix compress signature
  - `8C` = 0x80 (block mode) + 12 (max bits)

### Multi-Block Files

Large files (>32KB) are split into 32KB blocks with an index structure:

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | h0: `num_blocks * 256` (e.g., 0x200 for 2 blocks, 0x600 for 6 blocks) |
| 0x04 | 4 | h1: Always 0 |
| 0x08 | 8 | Reserved |
| 0x10 | 4×N | Block offset table (each points to a compressed block) |

The h0 field encodes the block count:
- Byte 0: Loop counter (starts at 0, used by module during iteration)
- Byte 1: Number of blocks
- This gives the pattern h0 = num_blocks × 256 when byte 0 is 0

Each block offset points to a standard compressed block (8-byte header). Decompress all blocks in order and concatenate. The final block may be smaller than 32KB.

## Key Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `HEADER_SIZE` | 0x90 (144) | Size of the main TBAFS header |
| `ROOT_ENTRIES_OFFSET` | header[0x18] | Read from archive header (typically 0x114) |
| `ENTRY_SIZE` | 0x40 (64) | Size of each directory entry |
| `BLOCK_ALIGNMENT` | 16 | Alignment boundary for entries and data blocks |
| `LZW_BLOCK_SIZE` | 32768 | Maximum decompressed size per LZW block |
| `MAX_ENTRIES_PER_BLOCK` | 16 | Maximum entries scanned per block (0x1b4c: cmp r4, 0x10) |
| `MULTIBLOCK_INDEX_SIZE` | 0x110 (272) | Bytes read for multi-block index |

## Directory Structure

- Root directory entries start at offset specified in **header[0x18]** (typically 0x114)
- Root entry count is in **header[0x1C]**
- Subdirectory entries are located via a **directory block header**

### Directory Block Header

Each subdirectory's `data_position` points to a block header that describes where the directory's entries are located:

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | h0: Always 144 (0x90) - equals directory header size |
| 0x04 | 4 | h1: Always 0 |
| 0x08 | 4 | First entry block position |
| 0x0C | 4 | Count of entries in first block |
| 0x10 | 4 | Second entry block position (0 if none) |
| 0x14 | 4 | Count of entries in second block |
| ... | ... | Additional (position, count) pairs until position is 0 |

**Example**: A directory with 25 entries split across two non-contiguous blocks:
- Entry block 1 at 0x247C0 with 18 entries
- Entry block 2 at 0x353F0 with 7 entries

The header would contain: `[pos=0x247C0, count=18, pos=0x353F0, count=7, pos=0, count=0]`

### Finding Directory Entries

1. For root directory: read entries directly from header[0x18] for header[0x1C] entries
2. For subdirectories: read the directory block header at data_position
3. Iterate through (position, count) pairs until position is 0
4. For each pair, read `count` entries starting at `position`

## End Markers

A type value of `0xFFFFFFFF` marks the end of entries in a contiguous block. When iterating entries using explicit counts from the directory block header, end markers can be ignored.

The module also limits scanning to 16 entries per block (`cmp r4, 0x10` at 0x1b4c), providing a hard upper bound even if no end marker is present.

## Example: Parsing a TBAFS Archive

```python
import struct

# Read and validate header
magic = file.read(4)
assert magic == b'TAFS'
version = struct.unpack('<I', file[4:8])[0]
assert version == 0xC8  # Required by module

# Find root entries - position and count from header
root_entries_start = struct.unpack('<I', file[0x18:0x1C])[0]  # Typically 0x114
root_entry_count = struct.unpack('<I', file[0x1C:0x20])[0]

# Parse an entry (64 bytes)
entry = file[offset:offset+64]
entry_type = struct.unpack('<I', entry[0x00:0x04])[0]   # 1=file, 2=dir, -1=end
load_addr = struct.unpack('<I', entry[0x04:0x08])[0]
exec_addr = struct.unpack('<I', entry[0x08:0x0C])[0]
size = struct.unpack('<I', entry[0x0C:0x10])[0]
attributes = struct.unpack('<I', entry[0x10:0x14])[0]
name = entry[0x14:0x28].split(b'\x00')[0].decode('latin-1')  # 20 bytes
mode_byte = entry[0x3B]                                      # 2 = multi-block
data_position = struct.unpack('<I', entry[0x3C:0x40])[0]     # Block position

# Extract single-block file data
if entry_type == 1 and mode_byte != 2:  # Single-block file
    h0 = struct.unpack('<I', file[data_position:data_position+4])[0]
    compression_type = (h0 >> 24) & 0xFF
    uncomp_size = h0 & 0xFFFFFF

    if compression_type == 2:  # Squash compressed (8-byte header)
        comp_size = struct.unpack('<I', file[data_position+4:data_position+8])[0]
        lzw_data = file[data_position+8:data_position+8+comp_size]
        # Decompress using 12-bit LZW
    elif compression_type == 0:  # Raw (4-byte header)
        raw_data = file[data_position+4:data_position+4+uncomp_size]

# Extract multi-block file data
if entry_type == 1 and mode_byte == 2:  # Multi-block file
    h0 = struct.unpack('<I', file[data_position:data_position+4])[0]
    num_blocks = h0 // 256
    result = b''
    for i in range(num_blocks):
        block_pos = struct.unpack('<I', file[data_position+0x10+i*4:data_position+0x14+i*4])[0]
        # Read and decompress each block...
        result += decompress_block(block_pos)
```


## Data Location Algorithm

The `data_position` field (entry[0x3c]) points directly to the data block header.

### Single-Block Files

1. Read h0 at data_position
2. Determine compression type: `comp_type = (h0 >> 24) & 0xFF`
3. For Squash compressed (type 2): read h1 for compressed size, data at +8
4. For HCT1 compressed (type 1): read h1 for compressed size, data at +8 (speculative)
5. For raw (type 0): data at +4, size is h0 & 0xFFFFFF

### Multi-Block Files

Multi-block files are identified by a **mode byte** at entry offset 0x3B. When `entry[0x3B] == 2`:

1. Read multi-block index at data_position
2. h0 = num_blocks × 256, h1 = 0
3. Block offsets at +0x10, +0x14, +0x18, ...
4. Each offset points to a compressed block
5. Decompress all blocks and concatenate

## Implementation Notes

1. **Mixed compression**: A directory may contain both compressed and raw files. Check h0's high byte to determine format.

2. **Entry blocks**: Directories can have entries in multiple non-contiguous blocks. Always read the directory block header to find all entry locations.

## References

- [RISC OS Squash documentation](http://riscos.com/support/developers/prm/squash.html)
- [Unix compress format](http://fileformats.archiveteam.org/wiki/Compress_(Unix))
- [TBAFS on Archive Team](http://fileformats.archiveteam.org/wiki/TBAFS)
- `docs/NotesFromDisassembly.md` - Disassembly notes from TBAFSModR,ffa module

## Version History

- 2026-01-20: Added speculative documentation for Type 1 (HCT1) Huffman compression, derived from disassembly analysis. No test archives available - treat as unverified.
- 2026-01-20: **Major revision**: Documented correct block header formats (8-byte for compressed, 4-byte for raw). Documented multi-block index format (h0 = num_blocks × 256). Documented directory block header format with entry block positions. Removed incorrect marker block documentation - those structures are actually directory block headers.
- 2026-01-20: **Critical fix**: Corrected entry layout from disassembly. Entry[0x00]=type, entry[0x14]=filename (20 bytes), entry[0x3c]=data position. Root entry table position is read from header[0x18], not hardcoded.
- 2026-01-18: Initial reverse-engineered specification
