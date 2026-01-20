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
| 0x18 | 4 | Unknown |
| 0x1C | 4 | Entry count in root directory |

Note: The module validates bytes 4-7 == 0xC8 as a version check.

## Directory Entry (64 bytes)

Each file or directory is described by a 64-byte entry:

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | Data offset (see note below) |
| 0x04 | 4 | Entry type: 1=file, 2=directory, 0xFFFFFFFF=end |
| 0x08 | 4 | RISC OS load address |
| 0x0C | 4 | RISC OS exec address |
| 0x10 | 4 | Uncompressed file size (0 for directories) |
| 0x14 | 4 | Flags/attributes |
| 0x18 | 24 | Filename (null-terminated) |

**Note on compression**: The compression type is NOT stored in the directory entry flags. It is encoded in the **data block header** (h1 high byte). The flags field at offset 0x14 appears to be RISC OS file attributes.

### Data Offset Field

For files where the data offset points to a valid data block:
- `data_offset - 4` = start of the 12-byte data block header

For the first file in a directory:
- May contain a sentinel value (e.g., parent directory block offset)

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

TBAFS supports multiple storage formats, identified by a **compression type** encoded in the data block header.

### Data Block Header (12 bytes)

All data blocks share a common 12-byte header structure:

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | h0: Workspace/buffer size |
| 0x04 | 4 | h1: Packed field: `(compression_type << 24) \| size_field` |
| 0x08 | 4 | h2: Compressed data size (for type 2) or other |

### Compression Types (from disassembly)

The **high byte of h1** (bits 24-31) indicates the compression type:

| Type | h1 Pattern | Description |
|------|------------|-------------|
| 0 | `0x00xxxxxx` | Raw/uncompressed data |
| 1 | `0x01xxxxxx` | HCT1/CompMod compressed (different from Squash) |
| 2 | `0x02xxxxxx` | Squash compressed (LZW) |

**Type 1 (HCT1)**: The module checks for "HCT1" magic at the start of the compressed data. This is a different compression format (CompMod) from Squash. Not yet supported by this extractor.

### Type 2: Squash Compressed Block

For compressed blocks (h1 high byte = 0x02):
- h0: Workspace size for decompression
- h1: `0x02xxxxxx` where low 24 bits = size field
- h2: Compressed data size in bytes
- Offset +12: LZW data starts (magic `1F 9D 8C`)

Example: `h1 = 0x02000113` → type=2 (compressed), size_field=275

### Type 0: Raw/Uncompressed Block

For uncompressed blocks (h1 high byte = 0x00):
- h0: Buffer/workspace size
- h1: `0x00xxxxxx` where **low 24 bits = actual file size**
- h2: May contain additional size info
- Offset +12: Raw file data starts

Example: `h1 = 0x00000ccd` → type=0 (raw), size=3277 bytes

### Detecting Storage Format

To determine compression type without heuristics:
```python
h1 = read_u32(block_header + 4)
compression_type = (h1 >> 24) & 0xFF
size_field = h1 & 0xFFFFFF

if compression_type == 2:
    # Squash compressed: read h2 for compressed size
    comp_size = read_u32(block_header + 8)
    lzw_data = data[block_header + 12 : block_header + 12 + comp_size]
elif compression_type == 0:
    # Raw: size_field is the actual file size
    raw_data = data[block_header + 12 : block_header + 12 + size_field]
```

## Compression Format

TBAFS uses the RISC OS "Squash" compression, which is:
- 12-bit LZW (Lempel-Ziv-Welch)
- Compatible with Unix `compress -b 12`
- Magic bytes: `1F 9D 8C`
  - `1F 9D` = Unix compress signature
  - `8C` = 0x80 (block mode) + 12 (max bits)

### Multi-Block Files

Large files are split into 32KB (32768 byte) blocks:
1. Each block has its own 12-byte header
2. Blocks are 16-byte aligned
3. Concatenate decompressed blocks to reconstruct the file
4. Final block may be smaller than 32KB

## Key Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `HEADER_SIZE` | 0x90 (144) | Size of the main TBAFS header |
| `ROOT_DIR_RESERVED` | 0x80 (128) | Reserved block after header (zeros) |
| `ROOT_ENTRIES_OFFSET` | 0x110 (272) | Where root entries begin (HEADER_SIZE + ROOT_DIR_RESERVED) |
| `ENTRY_SIZE` | 0x40 (64) | Size of each directory entry |
| `BLOCK_ALIGNMENT` | 16 | Alignment boundary for entries and data blocks |
| `LZW_BLOCK_SIZE` | 32768 | Maximum decompressed size per LZW block |

## Directory Structure

- Root directory entries start at `dir_header_size + ROOT_DIR_RESERVED` (typically 0x110)
- Subdirectory entries are located after the parent directory's data blocks
- Scan forward from directory data_offset to find entries (may be 64KB+ ahead)
- Entries are 16-byte aligned (not 64-byte aligned from directory start)

### Finding Subdirectory Entries

Subdirectory entries are NOT immediately after the directory block. They follow the data blocks of files in the parent directory and may be in multiple non-contiguous blocks. To find them:

1. First, collect ALL directory data_offsets from the archive to establish boundaries
2. Each directory owns entries between its data_offset and the next directory's data_offset
3. Scan within this bounded range at 16-byte intervals
4. Entries may be separated by compressed file data - skip past invalid regions
5. End markers (`0xFFFFFFFF`) indicate end of an entry block but more entries may follow

### Non-Contiguous Entry Blocks

Directory entries can be split across multiple blocks in the file, separated by compressed data. For example, the Samples directory may have entries at offset 0x247C0, then compressed file data, then more entries at 0x353F0. Both blocks belong to the same directory.

The key insight is to use sibling directory boundaries: each directory's entries must be between its own data_offset and the next sibling directory's data_offset.

## End Markers

A type value of `0xFFFFFFFF` marks the end of an entry block in a directory. However, more entries for the same directory may exist further in the file (after compressed data).

## Example: Parsing a TBAFS Archive

```python
# Read and validate header
magic = file.read(4)
assert magic == b'TAFS'
version = struct.unpack('<I', file[4:8])[0]
assert version == 0xC8  # Required by module

# Find root entries
dir_header_size = struct.unpack('<I', file[0x0C:0x10])[0]
root_entries_start = dir_header_size + 0x80  # Typically 0x110

# Parse an entry
entry = file[offset:offset+64]
data_offset = struct.unpack('<I', entry[0:4])[0]
entry_type = struct.unpack('<I', entry[4:8])[0]
load_addr = struct.unpack('<I', entry[8:12])[0]
size = struct.unpack('<I', entry[16:20])[0]
name = entry[24:48].split(b'\x00')[0].decode('latin-1')

# Extract file data
if entry_type == 1:  # File
    block_header = data_offset - 4
    h1 = struct.unpack('<I', file[block_header+4:block_header+8])[0]
    compression_type = (h1 >> 24) & 0xFF

    if compression_type == 2:  # Squash compressed
        comp_size = struct.unpack('<I', file[block_header+8:block_header+12])[0]
        lzw_data = file[block_header+12:block_header+12+comp_size]
        # Decompress using 12-bit LZW
    elif compression_type == 0:  # Raw
        file_size = h1 & 0xFFFFFF
        raw_data = file[block_header+12:block_header+12+file_size]
```

## Marker Blocks and Deferred Data

Some files have their data stored in a "deferred" location rather than immediately following their directory entry. These files are identified by a **marker block** at their data_offset position.

### Marker Block Structure

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | Always 0x90 (144) - equals HEADER_SIZE |
| 0x04 | 4 | Always 0x00 |
| 0x08 | 4 | Reserved (0) |
| 0x0C | 4 | Offset to first directory entry's type field |
| 0x10 | 4 | Count of directory entries in first block |
| 0x14 | 4 | Offset to second entry block (0 if none) |
| 0x18 | 4 | Count of entries in second block (0 if none) |

A marker block is identified by: `h0 == 144 && h1 == 0`

The +12 and +16 fields describe directory entries that follow this marker block. The marker file's actual data is stored AFTER these directory entries.

### Finding Deferred Data

The location of a marker file's data depends on the file size:

**Large files (> 32KB)**: Use the **shifted index pattern**
- Data is stored at the next file's multi-block index position
- Scan forward in data_offset order to find the next non-marker file's multi-block index
- That index contains the marker file's data blocks

**Small files (≤ 32KB)**: Data at **end of region**
- For non-root files: Data follows all files that come AFTER this marker in data_offset order (within the same directory tree)
- For root-level files: Data is at the very END of all archive data

**Last marker by data_offset**: If the marker is the last file in data_offset order (no files come after), its data is stored at the **very end of the archive file**. The LZW block ends exactly at the archive's file size boundary (16-byte aligned). To find this block, scan backward from the archive end in 16-byte steps until finding LZW magic (1F 9D) with a size_field matching the expected file size.

### Multi-Block Index Structure

Large files use a multi-block index containing a table of block offsets:

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | Index header (typically 288 = 0x120) |
| 0x04 | 4 | Some count or flags |
| 0x10+ | 4×N | Table of block offsets (each offset - 4 = block header) |

Each offset in the table points to an LZW block. Decompress all blocks in order and concatenate.

## Data Location Algorithm

For files with `data_offset ≠ 0x410`:
1. Compute `prev_header = data_offset - 4`
2. Check block type at `prev_header`:
   - **LZW block**: Magic `1F 9D` at +12 → skip past (header + 12 + comp_size, aligned)
   - **Uncompressed block**: `h1` = file size → skip past (header + 8 + h1, aligned)
   - **Multi-block index**: Offset table entries → find last block end, skip past
   - **Marker block**: `h0=144, h1=0` → use deferred data algorithm
3. Our data starts at the position after skipping past the previous block

For files with `data_offset == 0x410`:
- This is a **first-in-block** file
- Block position is: `entry.offset + entry.data_offset`

## Implementation Notes

1. **Relative data_offset**: The first file in a directory group has data_offset `0x410`. Add this to the entry's offset to find the data block header: `entry.offset + 0x410`.

2. **Global boundary calculation**: To correctly parse all entries, first scan the entire archive to find all directories, then use their data_offsets as boundaries when parsing each directory's contents.

3. **Mixed compression**: A single directory may contain both compressed (LZW) and uncompressed files. Check each block's magic bytes to determine the format.

4. **Marker file ordering**: Marker files' data is interleaved with regular data based on data_offset ordering. A marker's data goes after all non-marker files with higher data_offsets (within the tree) have their data.

## References

- [RISC OS Squash documentation](http://riscos.com/support/developers/prm/squash.html)
- [Unix compress format](http://fileformats.archiveteam.org/wiki/Compress_(Unix))
- [TBAFS on Archive Team](http://fileformats.archiveteam.org/wiki/TBAFS)
- `docs/NotesFromDisassembly.md` - Disassembly notes from TBAFSModR,ffa module

## Version History

- 2026-01-19: Documented marker block extended structure (+12/+16 fields)
- 2026-01-19: Added "last marker at archive end" pattern for final marker files
- 2026-01-19: Major update from disassembly - compression type in h1 high byte, not entry flags
- 2026-01-19: Added marker blocks, deferred data, and data location algorithm
- 2026-01-18: Initial reverse-engineered specification
