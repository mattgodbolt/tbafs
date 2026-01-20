# Notes from TBAFSModR Disassembly

Reverse engineering notes from disassembling `TBAFSModR,ffa` - the RISC OS relocatable module for TBA FS (Read Only) version 1.01, dated 14 Nov 1996.

## Module Overview

- **Title**: TBAFSMod
- **Help String**: "TBA FS Module (Read Only) 1.01 (14 Nov 1996)"
- **No SWIs provided** - this module consumes SWIs, doesn't provide them
- Registers as a filing system with FileSwitch

### Key SWI Calls Used

| SWI | Name | Purpose |
|-----|------|---------|
| 0x2000C | XOS_GBPB | Read data blocks from archive |
| 0x2000D | XOS_File | File operations |
| 0x2001E | XOS_Module | Memory allocation (reason 6=claim, 7=free) |
| 0x20009 | XOS_FSControl | FileSwitch control |
| 0x42701 | Squash_Decompress | LZW decompression |

## Compression Type Detection

**Location**: 0x1e58-0x1e94

The compression type is read directly from the **on-disk data block header**. At 0x1e64-0x1e70, OS_GBPB reads 4 bytes from the archive file into a buffer:

```arm
0x1e64: add r2, r8, 0x18          ; Destination buffer at [r8+0x18]
0x1e68: ldr r1, [ip, 0x18]        ; File handle
0x1e6c: mov r0, 3                 ; OS_GBPB reason 3 (read at position)
0x1e70: svc 0xc                   ; XOS_GBPB - READ 4 BYTES FROM DISK
```

The compression type is then extracted from the **high byte** of this 32-bit on-disk field:

```arm
0x1e74: ldr r0, [r8, 0x18]        ; Load 32-bit value just read from disk
0x1e78: lsr r3, r0, 0x18          ; Extract high byte as compression type
0x1e7c: bic r0, r0, 0xff000000    ; Mask out type, keep size in low 24 bits
0x1e80: str r0, [r8, 0x18]        ; Store back the size
0x1e84: add pc, pc, r3, lsl 2     ; Jump table dispatch based on type
```

**On-disk format**: The 4-byte field is `(compression_type << 24) | size_in_bytes`

### Compression Type Values

| Type | Handler | Description |
|------|---------|-------------|
| 0 | 0x1e98 | Raw/uncompressed - simple sequential read |
| 1 | 0x1ea8 | **HCT1/CompMod compressed** - uses built-in decompressor |
| 2 | 0x1edc | **Squash compressed** - calls SWI 0x42701 |

**Important**: This differs from FORMAT.md which claims "flags = 3" indicates Squash compression. The actual encoding appears to be a packed 32-bit word: `(compression_type << 24) | size_in_bytes`.

### Compression Type 1: HCT1/CompMod Format

At 0x14d0, the code checks for "HCT1" magic:
```arm
0x14d0: ldr r3, [r1]          ; Load first 4 bytes of compressed data
0x14d4: ldr r4, [0xf10]       ; Load "HCT1" magic (0x31544348)
0x14d8: cmp r3, r4            ; Check for HCT1 header
0x14dc: subne r0, pc, 0x30    ; Error: "Not a CompMod Archive!"
```

This is a different compression format from Squash. The module has built-in decompression routines for HCT1 format (0xefc-0x1510).

## Multi-Block File Handling

**Location**: 0xc24-0xc78

Large files are split into 32KB blocks. The block size is stored at workspace offset [sl, 0x24]:

```arm
; Block size default: 0x8000 (32768 bytes)
0xc24: ldr r0, [sl, 0x24]         ; Load block size (default 0x8000)
; ... loop processing each block ...
0xc78: ; End of block processing loop
```

Each block is decompressed independently and the results are concatenated. The loop continues until the full file size (from the directory entry) has been reconstructed.

## Squash Decompression Call

**Location**: 0x1edc-0x1f18

```arm
0x1efc: mov r0, 4                 ; Reason code 4 = decompress
0x1f00: ldr r1, [sl, 0x1c]        ; Source buffer
0x1f04: ldr r2, [sl, 0x18]        ; Source pointer
0x1f08: add r2, r2, 4             ; Skip 4 bytes (header?)
0x1f0c: ldr r3, [r2, -4]          ; Compressed size
0x1f10: add r4, r8, 0x1c          ; Destination buffer
0x1f14: ldr r5, [sl, 0x24]        ; Output buffer size
0x1f18: svc 0x42701               ; Squash_Decompress
```

## Directory Entry Structure

Each directory entry is **64 bytes** (0x40), stored at workspace offset 0x1d0.

### Entry Layout (from disassembly analysis)

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | Status/offset (0xFFFFFFFF = empty/end marker) |
| 0x14 | 20+ | Filename (used for lookup comparison) |

The entry copy function at 0x1ce8 copies all 64 bytes:
```arm
0x1cec: add r8, sb, r4, lsl 6     ; r8 = base + index * 64
0x1cf0: add sb, ip, 0x5d0         ; destination = workspace + 0x5d0
0x1cf4: ldm r8!, {r0-r7}          ; load 32 bytes
0x1cf8: stm sb!, {r0-r7}          ; store 32 bytes
0x1cfc: ldm r8!, {r0-r7}          ; load 32 bytes
0x1d00: stm sb!, {r0-r7}          ; store 32 bytes
```

### Directory Lookup (0x1af4)

```arm
0x1afc: add sl, ip, 0x50          ; Directory block table
0x1b00: add sb, ip, 0x1d0         ; Directory entries array
; Loop through blocks (up to 15)
0x1b10: ldr r0, [sl, r2, lsl 3]   ; Load block pointer (8 bytes per entry)
; Loop through entries (up to 16 per block)
0x1b28: add r8, sb, r4, lsl 6     ; Entry = base + index * 64
0x1b2c: ldr r0, [r8]              ; Load status
0x1b30: cmn r0, 1                 ; Check for -1 (empty)
0x1b38: add r0, r8, 0x14          ; Filename at entry + 0x14
0x1b40: bl 0x20f8                 ; Compare with search string
```

## Workspace Memory Layout

The module allocates workspace at the address in r12 (ip). Key offsets:

| Offset | Size | Contents |
|--------|------|----------|
| 0x10 | 4 | Pointer to file info structure |
| 0x18 | 4 | File handle for archive |
| 0x1c | 4 | Current directory pointer |
| 0x40 | 16 | Block header read buffer |
| 0x50 | 128 | Directory block table (15 entries × 8 bytes + padding) |
| 0x1d0 | 1024 | Directory entries cache (16 entries × 64 bytes) |
| 0x5d0 | 64 | Current entry info (copied from 0x1d0 array) |
| 0x5d0 | 4 | Object type |
| 0x5d4 | 4 | Load address |
| 0x5d8 | 4 | Exec address |
| 0x5dc | 4 | Length |
| 0x5e0 | 4 | Attributes |
| 0x9d0 | 272 | Cache block 1 |
| 0xae0 | 272 | Cache block 2 |
| 0xbf0 | 16 | Search context (block index, entry index, etc.) |
| 0xbf8 | 8 | Current file ID (for matching) |

## Data Reading Functions

### Read Block Header (0x202c)
Reads 16 bytes to workspace+0x40:
```arm
0x2030: mov r0, 3                 ; OS_GBPB reason 3 (read at position)
0x2034: ldr r1, [ip, 0x18]        ; File handle
0x2038: add r2, ip, 0x40          ; Destination buffer
0x203c: mov r3, 0x10              ; 16 bytes
0x2044: svc 0x2000c               ; XOS_GBPB
```

### Read Directory Block Table (0x204c)
Reads 128 bytes to workspace+0x50

### Read Directory Entries (0x2070)
Reads 1024 bytes (16 × 64) to workspace+0x1d0

## FSEntry Dispatch Tables

### FSEntry_File (around 0x568)
| Reason | Handler | Notes |
|--------|---------|-------|
| 3 | 0x970 | Returns "read only" error |
| 4 | Returns | Returns 0x40 alignment |
| 6,7,8,9 | Various | Other file operations |

### FSEntry_Func (around 0x648)
| Reason | Handler | Notes |
|--------|---------|-------|
| 8 | 0x67c | Read directory entries |
| 14 (0xe) | 0x680 | Read directory entries + info |
| 15 (0xf) | 0x6e4 | Read full directory info |
| 21 (0x15) | 0x780 | Open directory |
| 22 (0x16) | 0x7d4 | Close directory |
| 30 (0x1e) | 0x808 | Read boot option |

## Header Validation

**Location**: 0x1aa0-0x1aac

The module validates the first 8 bytes of the archive header:

```arm
0x1aa0: ldm r2, {r0, r1}          ; Load first 8 bytes of header
0x1aa4: ldr r2, [0x1a7c]          ; Load "TAFS" magic (0x53464154)
0x1aa8: cmp r0, r2                ; Check magic == "TAFS"
0x1aac: cmpeq r1, 0xc8            ; Check second word == 0xC8 (200)
```

**Key Finding**: The second 32-bit word of the header MUST be 0xC8 (200 decimal). This is a version check.

## Magic Number Check

**Location**: 0x184

```arm
0x180: ldr r0, [sl, 0x58]         ; Load first 4 bytes of image
0x184: ldr r2, [0xe0]             ; Load expected magic (0x53464154 = "TAFS")
0x188: cmp r0, r2                 ; Compare
0x18c: bne 0x1d0                  ; Error if not TBAFS image
```

## Error Messages (from strings)

- "Error Initialising Module"
- "Not a TBAFS image file"
- "This item is locked to stop changes being made to it"
- "Directory not empty"
- "Path not found"
- "Already exists"
- "Serious! TBAFS File I/O Error"
- "This file has been left open from a previous operation"
- "Access violation"
- "You can not open a TBAFS image within another TBAFS image"
- "This version of TBAFS is read only!"
- "Unknown Call to TBAFSmod"
- "Unknown Compression Type"
- "Cache Size Too Small"

## Questions / Unknowns

1. The exact layout of the on-disk directory entry vs the in-memory format
2. How the "data_offset" field in entries maps to actual file positions
3. The meaning of the directory block table entries (8 bytes each)
4. ~~Whether type 1 compression is a variant or something else entirely~~ **ANSWERED**: Type 1 is HCT1/CompMod format, a completely different compression scheme with its own built-in decompressor
5. The structure of multi-block file indices (partial answer: 32KB blocks, loop at 0xc24-0xc78)

## Files Generated

- `TBAFSModR_disasm.txt` - Raw radare2 disassembly
- `TBAFSModR_annotated.txt` - Disassembly with header documentation
