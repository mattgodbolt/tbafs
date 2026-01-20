# TBAFS Project - Claude Code Context

This project reverse-engineers the TBAFS archive format used by RISC OS computers.

## Project Status

**Status:** In progress - Fixing marker file extraction (JukeboxMod, ScrollText, ReadME)

## Reference Files

- **comparison/Blurp/**: Contains correctly extracted Blurp archive for comparison
- Filenames use RISC OS format: `filename,filetype` (e.g., `!Boot,feb` where 0xfeb = Obey file)
- Graphics files are type 0x004 (sprite files)

## Key Discoveries

### Format Overview
- Magic: `TAFS` (4 bytes at offset 0)
- Compression: 12-bit LZW (Unix compress compatible, magic `1F 9D`)
- Large files split into 32KB blocks
- Directory entries may be non-contiguous (split across multiple blocks)

### Directory Entry Structure (64 bytes each)
| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 4 | Data offset (+4 to block header) |
| 0x04 | 4 | Type: 1=file, 2=dir, 0xFFFFFFFF=end |
| 0x08 | 4 | RISC OS load address (filetype in bits 8-19) |
| 0x0C | 4 | RISC OS exec address (timestamp) |
| 0x10 | 4 | Uncompressed file size |
| 0x14 | 4 | Flags (3 = Squash compressed) |
| 0x18 | 24 | Filename (null-terminated) |

### Compressed Data Block (12-byte header)
- Bytes 0-3: Workspace size (not actual uncompressed size!)
- Bytes 4-7: Flags (0x020001xx pattern)
- Bytes 8-11: Compressed data size
- Bytes 12+: LZW data (starts with `1F 9D 8C`)

### Entry Location Algorithm
- First collect ALL directory data_offsets globally
- Each directory owns entries between its data_offset and next directory's data_offset
- Scan at 16-byte intervals within bounded range
- End markers (0xFFFFFFFF) don't terminate search - continue scanning for more blocks

### Data Location Algorithm (IMPORTANT - "Shifted Index" Pattern)

**General pattern**: `data_offset` points to `prev_block_header + 4`. Skip past the previous block to find our data.

**Multi-block files have a "shifted index" pattern**:
- Each multi-block file's index contains data for the PREVIOUS multi-block file, not itself
- Example: LEVELS index at 0x20d00 contains JukeboxMod data; NiceDrums index contains LEVELS data
- To find a multi-block file's data, skip past its prev_header to the NEXT file's index position

**Marker blocks** (h0=144, h1=0):
- Some files have a "marker" at their prev_header instead of actual data
- These marker files have their data at the END of the region they skip over
- JukeboxMod: marker, data at LEVELS' index position (skip-past finds it correctly)
- ScrollText: marker, raw data after all Samples files
- ReadME: marker, LZW data at very end of archive (after Ooh (Rev))

**Data offset interpretations**:
- `data_offset = 0x410`: First file in block, relative offset (header = entry + 0x410)
- `data_offset != 0x410`: Absolute offset to prev_header + 4 (header = data_offset - 4)

## File Structure

```
tbafs/
├── tbafs.py          # Main extractor (Python 3.10+)
├── adfs.py           # ADFS E format disc image creator
├── test.sh           # Reproducible test script (verifies MD5)
├── FORMAT.md         # Full format specification (TBAFS)
├── README.md         # User documentation
├── LICENSE           # MIT License
├── CLAUDE.md         # This file
├── samples/          # Test .b21 files
│   ├── Blurp.b21
│   └── BlurpRPC.b21
├── tmp/              # Test outputs (gitignored)
└── docs/             # Reference documentation
    └── squash.html   # RISC OS Squash docs
```

## ADFS Image Creator (adfs.py)

Creates ADFS E format (800KB) floppy disc images compatible with RISC OS emulators.

### Key Implementation Details

- **Format**: ADFS E (NewDir) - 800KB, 1024-byte sectors
- **Directory format**: NewDir ("Nick" signature) - NOT OldDir ("Hugo")
- **Filename encoding**: CR terminator (0x0D) for names < 10 chars; full 10-char names have no terminator
  - Correct: `!Blurp\x0d` (CR terminated)
  - Wrong: `!Blurð` (top-bit on last char = OldDir format)
- **Map format**: New map with zone 0 duplicated at sectors 0 and 1
- **Root directory**: Sector 2 (offset 0x800)

## Testing

```bash
./test.sh                                        # Reproducible extraction test (verifies MD5)
python3 tbafs.py list -v samples/Blurp.b21      # List contents
python3 tbafs.py extract samples/Blurp.b21 -o tmp/extracted
find tmp/extracted -type f | wc -l              # Count files (should be 49)
```

## Claude Code Preferences

- **Do NOT use `python3 -c '...'`** - Write test scripts to `./tmp/` and run those instead
- **Do NOT use `cat` or heredocs to create files** - Use the Write tool instead
- Use `./tmp/` for all temporary files and test outputs
- Use virtual environments for any pip installs (e.g., `./tmp/venv/`)
- **No heuristics or fallbacks** - The format should have a simple, parsimonious explanation

## References

- [TBAFS - Archive Team](http://fileformats.archiveteam.org/wiki/TBAFS)
- [RISC OS Squash documentation](http://riscos.com/support/developers/prm/squash.html)
- [riscosarc](https://github.com/mjwoodcock/riscosarc) - Similar extractor (no TBAFS support)
