# TBAFS Project - Claude Code Context

This project reverse-engineers the TBAFS archive format used by RISC OS computers.

## Project Status

**Status:** Stable - Disassembly findings encoded into code and documentation

## Reference Files

- **comparison/Blurp/**: Contains correctly extracted Blurp archive for comparison
- Filenames use RISC OS format: `filename,filetype` (e.g., `!Boot,feb` where 0xfeb = Obey file)
- Graphics files are type 0x004 (sprite files)

## Key Discoveries (Confirmed via Disassembly)

### Format Overview
- Magic: `TAFS` (4 bytes at offset 0)
- Compression: 12-bit LZW (Unix compress compatible, magic `1F 9D`)
- Large files split into 32KB blocks
- Directory entries may be non-contiguous (split across multiple blocks)

### Directory Entry Structure (64 bytes each)
| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 4 | Type: 1=file, 2=dir, 0xFFFFFFFF=end |
| 0x04 | 4 | RISC OS load address (filetype in bits 8-19) |
| 0x08 | 4 | RISC OS exec address (timestamp) |
| 0x0C | 4 | Uncompressed file size |
| 0x10 | 4 | RISC OS file attributes |
| 0x14 | 20 | Filename (null-terminated) |
| 0x3B | 1 | Mode byte (2 = multi-block file) |
| 0x3C | 4 | Data block position |

### Entry Validation (from disassembly)
- Entry termination uses end markers (0xFFFFFFFF) AND max 16 entries per block (0x1b4c: cmp r4, 0x10)
- No heuristic validation needed - format has explicit entry counts

### Block Header Format
- h0: `(compression_type << 24) | uncompressed_size`
- Type 0: Raw data at +4
- Type 1: HCT1/CompMod (not supported)
- Type 2: Squash/LZW, compressed_size at h1, data at +8

### Multi-Block Index (from disassembly at 0x2094)
- 272 bytes total (0x110)
- h0 byte 0: Loop counter (starts at 0)
- h0 byte 1: Number of blocks
- h1: Always 0
- Block offsets at +0x10 (4 bytes each)

### Mode Byte (from disassembly at 0x1fc8)
- Only `== 2` check for multi-block; anything else is single-block
- Located at entry offset 0x3B

### Directory Block Table
- Scans for `position == 0` (0x1b14: cmp r0, 0)
- Count field used for index-based lookup (0x1ba8: ldm r8, {r0, r1})

## File Structure

```
tbafs/
├── tbafs.py          # Main extractor (Python 3.9+)
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
