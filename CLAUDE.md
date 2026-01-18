# TBAFS Project - Claude Code Context

This project reverse-engineers the TBAFS archive format used by RISC OS computers.

## Project Status

**Status:** Complete - Full extraction working, all files extracted correctly

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

## File Structure

```
tbafs/
├── tbafs.py          # Main extractor (Python)
├── FORMAT.md         # Full format specification
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

## Testing

```bash
python3 tbafs.py list -v samples/Blurp.b21      # List contents
python3 tbafs.py extract samples/Blurp.b21 -o tmp/extracted
find tmp/extracted -type f | wc -l              # Count files (should be 49)
```

## References

- [TBAFS - Archive Team](http://fileformats.archiveteam.org/wiki/TBAFS)
- [RISC OS Squash documentation](http://riscos.com/support/developers/prm/squash.html)
- [riscosarc](https://github.com/mjwoodcock/riscosarc) - Similar extractor (no TBAFS support)
