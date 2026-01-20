#!/usr/bin/env python3
"""
TBAFS Archive Extractor

TBAFS is a proprietary archive format for RISC OS computers, created by TBA Software.
This tool can list and extract files from .b21 TBAFS archives.

The format uses 12-bit LZW compression (identical to Unix compress -b 12).
"""

import argparse
import struct
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

# Archive structure constants
TBAFS_MAGIC = b"TAFS"
HEADER_SIZE = 0x90  # 144 bytes - main TBAFS header
ROOT_DIR_RESERVED = 0x80  # 128 bytes - reserved block after header
ROOT_ENTRIES_OFFSET = HEADER_SIZE + ROOT_DIR_RESERVED  # 0x110
ENTRY_SIZE = 0x40  # 64 bytes per directory entry
BLOCK_ALIGNMENT = 16  # Entries/blocks aligned to 16 bytes
LZW_BLOCK_SIZE = 32768  # 32KB decompressed blocks for large files

# LZW compression constants
LZW_MAGIC = b"\x1f\x9d"
LZW_MAX_BITS = 12
LZW_CLEAR_CODE = 256

# Compression types (encoded in high byte of h1 field in data block header)
COMP_TYPE_RAW = 0  # Type 0: Uncompressed/raw data
COMP_TYPE_HCT1 = 1  # Type 1: HCT1/CompMod compressed (not supported)
COMP_TYPE_SQUASH = 2  # Type 2: Squash/LZW compressed
LZW_INITIAL_BITS = 9
MAX_COMPRESSED_SIZE = 500_000  # Sanity check limit for compressed block size

# Entry type constants
ENTRY_TYPE_FILE = 1
ENTRY_TYPE_DIR = 2
ENTRY_TYPE_END = 0xFFFFFFFF

# Compression flags
FLAGS_COMPRESSED = 3


# RISC OS filetype names for common types
FILETYPES = {
    0xFFF: "Text",
    0xFFE: "Command",
    0xFFD: "Data",
    0xFFC: "Utility",
    0xFFB: "BASIC",
    0xFFA: "Module",
    0xFF9: "Sprite",
    0xFF8: "Absolute",
    0xFF7: "BBC font",
    0xFF6: "Font",
    0xFF5: "PoScript",
    0xFF4: "Printout",
    0xFF2: "Config",
    0xFEB: "Obey",
    0xFEA: "Desktop",
    0xFE6: "UNIX Ex",
    0xFD7: "TaskExec",
    0xFCA: "Squash",
    0xFC9: "SunRastr",
    0xDDC: "Archive",
    0xCB6: "MS Wave",
    0xCB5: "Sample",
    0xC85: "JPEG",
    0xAFF: "DrawFile",
    0x695: "GIF",
    0x004: "UnkData",  # Unknown data type often seen
}


def align_to(offset: int, alignment: int = BLOCK_ALIGNMENT) -> int:
    """Round offset up to next alignment boundary."""
    return (offset + alignment - 1) & ~(alignment - 1)


def parse_h1_field(h1: int) -> tuple[int, int]:
    """Parse the h1 field from a data block header.

    The h1 field is a packed 32-bit value:
    - Bits 24-31: compression type (0=raw, 1=HCT1, 2=Squash)
    - Bits 0-23: size field (meaning depends on compression type)

    Returns (compression_type, size_field).
    """
    compression_type = (h1 >> 24) & 0xFF
    size_field = h1 & 0xFFFFFF
    return compression_type, size_field


def _create_initial_dictionary() -> dict[int, bytes]:
    """Create initial LZW dictionary with single-byte codes 0-255."""
    return {i: bytes([i]) for i in range(256)}


class TBAFSExtractionError(Exception):
    """Raised when file data cannot be extracted."""

    pass


# Pre-compiled struct formats for header and entry parsing
HEADER_STRUCT = struct.Struct("<4I")  # root_alloc, unknown1, dir_header_size, reserved
ENTRY_STRUCT = struct.Struct("<6I")  # data_offset, type, load, exec, size, flags


@dataclass
class TBAFSHeader:
    """TBAFS archive header."""

    magic: str
    root_alloc: int
    unknown1: int
    dir_header_size: int
    first_entry_offset: int
    entry_count: int


@dataclass
class DirEntry:
    """A directory entry in a TBAFS archive."""

    offset: int  # Position of this entry in file
    data_offset: int  # Offset to data (for files) or subdir block (for dirs)
    entry_type: int  # 1=file, 2=directory, 0xFFFFFFFF=end
    load_addr: int  # RISC OS load address (contains filetype)
    exec_addr: int  # RISC OS exec address (timestamp)
    size: int  # Uncompressed size (0 for directories)
    flags: int  # Compression flags (3 = Squash compressed)
    name: str  # Filename
    parent_path: str  # Path to parent directory

    @property
    def filetype(self) -> int | None:
        """Extract RISC OS filetype from load address."""
        if (self.load_addr & 0xFFF00000) == 0xFFF00000:
            return (self.load_addr >> 8) & 0xFFF
        return None

    @property
    def filetype_name(self) -> str:
        """Get human-readable filetype name."""
        ft = self.filetype
        if ft is None:
            return "---"
        return FILETYPES.get(ft, f"{ft:03X}")

    @property
    def is_file(self) -> bool:
        return self.entry_type == ENTRY_TYPE_FILE

    @property
    def is_directory(self) -> bool:
        return self.entry_type == ENTRY_TYPE_DIR

    @property
    def is_end(self) -> bool:
        return self.entry_type == ENTRY_TYPE_END

    @property
    def is_compressed(self) -> bool:
        return self.flags == FLAGS_COMPRESSED

    @property
    def full_path(self) -> str:
        if self.parent_path:
            return f"{self.parent_path}/{self.name}"
        return self.name


class LZWDecompressor:
    """
    12-bit LZW decompressor compatible with RISC OS Squash format.

    This is equivalent to Unix 'compress -b 12' format.
    The compressed data starts with magic bytes 0x1F 0x9D followed by
    a flags byte (0x8C = block mode + 12 bits max).
    """

    def __init__(self, max_bits: int = LZW_MAX_BITS):
        self.max_bits = max_bits
        self.max_code = (1 << max_bits) - 1
        self.clear_code = LZW_CLEAR_CODE

    def decompress(self, data: bytes) -> bytes:
        """Decompress LZW data."""
        if len(data) < 3:
            raise ValueError("Data too short for LZW")

        # Check magic
        if data[:2] != LZW_MAGIC:
            raise ValueError(f"Invalid LZW magic: {data[0]:02X} {data[1]:02X}")

        flags = data[2]
        max_bits = flags & 0x1F
        block_mode = bool(flags & 0x80)

        if max_bits > self.max_bits:
            raise ValueError(f"Unsupported max bits: {max_bits}")

        # Initialize dictionary with single-byte codes
        dictionary = _create_initial_dictionary()
        next_code = LZW_CLEAR_CODE + 1 if block_mode else LZW_CLEAR_CODE

        # Bit reading state
        bit_buffer = 0
        bits_in_buffer = 0
        data_pos = 3
        current_bits = LZW_INITIAL_BITS

        output = bytearray()
        prev_string = b""

        while data_pos < len(data) or bits_in_buffer >= current_bits:
            # Read more bytes into buffer if needed
            while bits_in_buffer < current_bits and data_pos < len(data):
                bit_buffer |= data[data_pos] << bits_in_buffer
                bits_in_buffer += 8
                data_pos += 1

            if bits_in_buffer < current_bits:
                break

            # Extract code
            code = bit_buffer & ((1 << current_bits) - 1)
            bit_buffer >>= current_bits
            bits_in_buffer -= current_bits

            # Handle clear code
            if block_mode and code == self.clear_code:
                dictionary = _create_initial_dictionary()
                next_code = LZW_CLEAR_CODE + 1
                current_bits = LZW_INITIAL_BITS
                prev_string = b""
                continue

            # Decode
            if code in dictionary:
                entry = dictionary[code]
            elif code == next_code and prev_string:
                # Special case: code not in dictionary yet
                entry = prev_string + prev_string[0:1]
            else:
                if not prev_string:
                    # First code must be in dictionary
                    if code < 256:
                        entry = bytes([code])
                    else:
                        raise ValueError(f"Invalid first code: {code}")
                else:
                    raise ValueError(f"Invalid code: {code}, next_code: {next_code}")

            output.extend(entry)

            # Add new dictionary entry
            if prev_string and next_code <= self.max_code:
                dictionary[next_code] = prev_string + entry[0:1]
                next_code += 1

                # Increase code size if needed
                if next_code > (1 << current_bits) - 1 and current_bits < max_bits:
                    current_bits += 1

            prev_string = entry

        return bytes(output)


class TBAFSArchive:
    """TBAFS archive reader."""

    def __init__(self, file: BinaryIO):
        self.file = file
        self.data = file.read()
        self.header = self._parse_header()
        self.decompressor = LZWDecompressor()
        # Cache for tracking sequential uncompressed extraction positions
        # Maps group_start_offset -> current_position
        self._uncompressed_stream_pos: dict[int, int] = {}

    def _parse_header(self) -> TBAFSHeader:
        """Parse the TBAFS header."""
        if len(self.data) < 32:
            raise ValueError("File too small for TBAFS header")

        magic = self.data[0:4]
        if magic != TBAFS_MAGIC:
            raise ValueError(f"Invalid magic: {magic!r}, expected {TBAFS_MAGIC!r}")

        root_alloc, unknown1, dir_header_size, _ = HEADER_STRUCT.unpack(self.data[4:20])
        first_entry_offset, entry_count = struct.unpack("<II", self.data[24:32])

        return TBAFSHeader(
            magic=magic.decode("ascii"),
            root_alloc=root_alloc,
            unknown1=unknown1,
            dir_header_size=dir_header_size,
            first_entry_offset=first_entry_offset,
            entry_count=entry_count,
        )

    def _parse_entry(self, offset: int, parent_path: str = "") -> DirEntry | None:
        """Parse a single directory entry at the given offset."""
        if offset + ENTRY_SIZE > len(self.data):
            return None

        entry_data = self.data[offset : offset + ENTRY_SIZE]

        data_offset, entry_type, load_addr, exec_addr, size, flags = ENTRY_STRUCT.unpack(
            entry_data[:24]
        )

        # Extract null-terminated name
        name_bytes = entry_data[24:48]
        null_pos = name_bytes.find(b"\x00")
        if null_pos != -1:
            name_bytes = name_bytes[:null_pos]
        name = name_bytes.decode("latin-1", errors="replace")

        return DirEntry(
            offset=offset,
            data_offset=data_offset,
            entry_type=entry_type,
            load_addr=load_addr,
            exec_addr=exec_addr,
            size=size,
            flags=flags,
            name=name,
            parent_path=parent_path,
        )

    def _is_valid_entry(self, entry: DirEntry | None) -> bool:
        """Check if an entry looks valid."""
        if not entry:
            return False
        if entry.entry_type not in (ENTRY_TYPE_FILE, ENTRY_TYPE_DIR):
            return False
        if not entry.name or len(entry.name) < 1:
            return False
        # Name should start with alphanumeric or !
        if not (entry.name[0].isalnum() or entry.name[0] in "!_"):
            return False
        # Load address should be RISC OS format
        return (entry.load_addr >> 20) == 0xFFF

    def _find_all_entries_in_range(
        self, start: int, end: int, parent_path: str = ""
    ) -> list[DirEntry]:
        """
        Find ALL valid directory entries within a byte range.

        This scans the entire range at 16-byte intervals, collecting all valid
        entries. Entries may be in multiple non-contiguous blocks separated by
        compressed file data.
        """
        entries = []
        pos = align_to(start)

        while pos < end and pos + ENTRY_SIZE <= len(self.data):
            entry = self._parse_entry(pos, parent_path)

            if entry and entry.entry_type == ENTRY_TYPE_END:
                # End marker - skip past it
                pos += BLOCK_ALIGNMENT
                continue

            if self._is_valid_entry(entry) and entry is not None:
                entries.append(entry)
                pos += ENTRY_SIZE  # Move past this 64-byte entry
            else:
                pos += BLOCK_ALIGNMENT  # Scan at 16-byte intervals

        return entries

    def _get_dir_content_start(self, entry: DirEntry) -> int:
        """
        Get the absolute position where a directory's content starts.

        For directories with data_offset=0x410 (sentinel), content starts at
        entry.offset + data_offset. Otherwise data_offset is already absolute.
        """
        if entry.data_offset == 0x410:
            return entry.offset + entry.data_offset
        return entry.data_offset

    def _collect_all_directory_boundaries(self) -> list[int]:
        """
        Scan the entire archive to find all directory content_start positions.

        Returns a sorted list of unique content_start positions for all directories.
        These positions define the boundaries between directory entry blocks.

        The scan is done at 16-byte intervals since entries are aligned.
        """
        content_starts: set[int] = set()

        # Scan entire file at 16-byte intervals to find directory entries
        pos = 0
        while pos < len(self.data) - ENTRY_SIZE:
            entry = self._parse_entry(pos, "")
            if entry and entry.entry_type == ENTRY_TYPE_DIR and self._is_valid_entry(entry):
                content_start = self._get_dir_content_start(entry)
                content_starts.add(content_start)
            pos += BLOCK_ALIGNMENT

        return sorted(content_starts)

    def iter_entries(
        self,
        dir_content_start: int | None = None,
        parent_path: str = "",
        global_boundaries: list[int] | None = None,
    ) -> Iterator[DirEntry]:
        """Iterate over all directory entries, recursively."""
        if dir_content_start is None:
            # Root directory: entries start at dir_header_size + ROOT_DIR_RESERVED
            start_offset = self.header.dir_header_size + ROOT_DIR_RESERVED

            # First pass: scan entire archive to find all directory content_start positions
            # These define the boundaries between directory entry blocks
            all_dir_offsets = self._collect_all_directory_boundaries()
            all_dir_offsets.append(len(self.data))  # Add EOF as final boundary

            # Collect root entries (fixed positions)
            root_entries = []
            offset = start_offset
            while offset < len(self.data):
                entry = self._parse_entry(offset, parent_path)
                if entry is None or entry.is_end:
                    break
                if self._is_valid_entry(entry):
                    root_entries.append(entry)
                offset += ENTRY_SIZE

            # Yield root entries and recurse into directories
            for entry in root_entries:
                yield entry
                if entry.is_directory:
                    # Use content_start position, not raw data_offset
                    content_start = self._get_dir_content_start(entry)
                    yield from self.iter_entries(content_start, entry.full_path, all_dir_offsets)
        else:
            # For subdirectories, use global boundaries to find our scan range
            start = dir_content_start

            # Find the end boundary: the smallest offset greater than ours
            end = len(self.data)
            if global_boundaries:
                for boundary in global_boundaries:
                    if boundary > start:
                        end = boundary
                        break

            # Scan for entries within our bounded range
            entries = self._find_all_entries_in_range(start, end, parent_path)

            # Yield entries and recurse into subdirectories
            for entry in entries:
                yield entry
                if entry.is_directory:
                    # Use content_start position, not raw data_offset
                    content_start = self._get_dir_content_start(entry)
                    yield from self.iter_entries(content_start, entry.full_path, global_boundaries)

    def _read_blocks_from(self, start_offset: int, target_size: int) -> bytes:
        """
        Read consecutive LZW blocks starting from an offset until target_size bytes.

        Large files are split into 32KB blocks. This reads and concatenates them.
        Raises TBAFSExtractionError if blocks cannot be read or decompressed.
        """
        result = bytearray()
        block = start_offset

        while len(result) < target_size:
            if block + 14 > len(self.data):
                raise TBAFSExtractionError(f"Block header at 0x{block:x} extends beyond file end")

            # Check for LZW magic
            magic = self.data[block + 12 : block + 14]
            if magic != LZW_MAGIC:
                raise TBAFSExtractionError(
                    f"Expected LZW magic at 0x{block + 12:x}, got {magic.hex()}"
                )

            comp_size = struct.unpack("<I", self.data[block + 8 : block + 12])[0]
            if comp_size == 0:
                raise TBAFSExtractionError(f"Zero compressed size at block 0x{block:x}")
            if comp_size > MAX_COMPRESSED_SIZE:
                raise TBAFSExtractionError(
                    f"Compressed size {comp_size} exceeds maximum at block 0x{block:x}"
                )

            lzw_start = block + 12
            compressed_data = self.data[lzw_start : lzw_start + comp_size]

            decompressed = self.decompressor.decompress(compressed_data)
            result.extend(decompressed)

            # Next block is aligned after this one
            end = block + 12 + comp_size
            block = align_to(end)

        # Trim to exact size
        return bytes(result[:target_size])

    def _check_lzw_magic(self, offset: int) -> bool:
        """Check if LZW magic exists at offset."""
        if offset + 2 > len(self.data):
            return False
        return self.data[offset : offset + 2] == LZW_MAGIC

    def _get_block_compression_type(self, block_pos: int) -> int | None:
        """Get the compression type from a data block header.

        The compression type is encoded in the high byte of h1 (offset +4).
        Returns None if position is invalid, otherwise returns:
        - COMP_TYPE_RAW (0): uncompressed
        - COMP_TYPE_HCT1 (1): HCT1/CompMod (not supported)
        - COMP_TYPE_SQUASH (2): Squash/LZW compressed
        """
        if block_pos + 8 > len(self.data):
            return None
        h1 = struct.unpack("<I", self.data[block_pos + 4 : block_pos + 8])[0]
        comp_type, _ = parse_h1_field(h1)
        return comp_type

    def _read_uncompressed_data(self, data_offset: int, size: int) -> bytes:
        """Read uncompressed data directly from an offset."""
        if data_offset + size > len(self.data):
            raise TBAFSExtractionError(
                f"Uncompressed data at 0x{data_offset:x} extends beyond file"
            )
        return self.data[data_offset : data_offset + size]

    def _is_multiblock_index(self, pos: int) -> tuple[bool, int | None]:
        """Check if position contains a multi-block index.

        Returns (is_multiblock, table_start) where table_start is the
        offset where the block offset table begins.

        Multi-block indices have h0=288 and the offset table at +20.
        h1 varies (seen: 512, 1536) and may indicate flags or block count.
        Individual blocks may be compressed (type 2) or raw (type 0).
        """
        if pos + 24 > len(self.data):
            return False, None

        h0, h1 = struct.unpack("<2I", self.data[pos : pos + 8])

        # Multi-block index signature: h0=288
        # Verify by checking if offset table at +20 points to valid blocks
        if h0 == 288:
            table_start = pos + 20
            first_val = struct.unpack("<I", self.data[table_start : table_start + 4])[0]
            if first_val > 0 and first_val < len(self.data):
                first_header = first_val - 4
                comp_type = self._get_block_compression_type(first_header)
                if comp_type in (COMP_TYPE_RAW, COMP_TYPE_SQUASH):
                    return True, table_start

        return False, None

    def _is_uncompressed_multiblock(self, pos: int) -> bool:
        """Check if a multi-block index contains uncompressed blocks.

        Looks at the first block's compression type to determine this.
        All multi-block indices have h0=288, h1=512 - the difference is
        in the compression type of the individual blocks they point to.
        """
        is_multi, table_start = self._is_multiblock_index(pos)
        if not is_multi or table_start is None:
            return False

        # Read first block offset and check its compression type
        first_offset_pos = table_start
        if first_offset_pos + 4 > len(self.data):
            return False
        val = struct.unpack("<I", self.data[first_offset_pos : first_offset_pos + 4])[0]
        if val == 0 or val >= len(self.data):
            return False

        first_block = val - 4
        comp_type = self._get_block_compression_type(first_block)
        return comp_type == COMP_TYPE_RAW

    def _read_multiblock_offsets(self, index_pos: int, table_start: int) -> list[int]:
        """Read the block header offsets from a multi-block index.

        Validates each offset by checking the block's compression type.
        """
        offsets = []
        consecutive_zeros = 0
        for i in range(100):  # Max 100 blocks (32KB each = 3.2MB max file)
            offset_pos = table_start + i * 4
            if offset_pos + 4 > len(self.data):
                break
            val = struct.unpack("<I", self.data[offset_pos : offset_pos + 4])[0]
            if val == 0:
                consecutive_zeros += 1
                # Stop after 2 consecutive zeros (end of offset table)
                if consecutive_zeros >= 2:
                    break
                continue
            consecutive_zeros = 0
            if val >= len(self.data):
                continue
            header = val - 4
            if header < 0:
                continue
            # Validate block by checking compression type
            comp_type = self._get_block_compression_type(header)
            if comp_type in (COMP_TYPE_RAW, COMP_TYPE_SQUASH):
                offsets.append(header)
        return sorted(set(offsets))

    def _extract_multiblock(self, index_pos: int, target_size: int) -> bytes:
        """Extract a multi-block file from its index position."""
        is_multi, table_start = self._is_multiblock_index(index_pos)
        if not is_multi or table_start is None:
            raise TBAFSExtractionError(f"Expected multi-block index at 0x{index_pos:x}")

        offsets = self._read_multiblock_offsets(index_pos, table_start)
        if not offsets:
            raise TBAFSExtractionError(f"No valid block offsets found at 0x{index_pos:x}")

        result = bytearray()
        remaining = target_size

        for header in offsets:
            comp_type = self._get_block_compression_type(header)

            if comp_type == COMP_TYPE_SQUASH:
                # Compressed: decompress LZW data
                comp_size = struct.unpack("<I", self.data[header + 8 : header + 12])[0]
                if comp_size <= 0 or comp_size > MAX_COMPRESSED_SIZE:
                    raise TBAFSExtractionError(
                        f"Invalid compressed size {comp_size} at 0x{header:x}"
                    )
                lzw_data = self.data[header + 12 : header + 12 + comp_size]
                decompressed = self.decompressor.decompress(lzw_data)
                result.extend(decompressed)
            elif comp_type == COMP_TYPE_RAW:
                # Uncompressed: size is in low 24 bits of h1, data at +12
                h1 = struct.unpack("<I", self.data[header + 4 : header + 8])[0]
                _, size_field = parse_h1_field(h1)
                block_size = min(size_field, remaining)
                result.extend(self.data[header + 12 : header + 12 + block_size])
                remaining -= block_size
            else:
                raise TBAFSExtractionError(
                    f"Unsupported compression type {comp_type} at 0x{header:x}"
                )

        return bytes(result[:target_size])

    def _skip_past_block(self, pos: int) -> int | None:
        """Skip past a block (single-block, uncompressed, or multi-block).

        Returns the position immediately after this block (aligned).
        """
        # Check for single-block LZW
        if self._check_lzw_magic(pos + 12):
            comp_size = struct.unpack("<I", self.data[pos + 8 : pos + 12])[0]
            if 0 < comp_size < MAX_COMPRESSED_SIZE:
                return align_to(pos + 12 + comp_size)

        # Check for uncompressed block
        h0, h1 = struct.unpack("<2I", self.data[pos : pos + 8])
        if 0 < h1 < 100000 and h1 <= h0 + 16:  # h1 close to h0
            return align_to(pos + 8 + h1)

        # Check for multi-block index
        is_multi, table_start = self._is_multiblock_index(pos)
        if is_multi and table_start is not None:
            offsets = self._read_multiblock_offsets(pos, table_start)
            if offsets:
                # Find the last block and skip past it
                last_header = max(offsets)
                if self._is_uncompressed_multiblock(pos):
                    # Uncompressed: header value is total block size (including header)
                    block_size = struct.unpack("<I", self.data[last_header : last_header + 4])[0]
                    return align_to(last_header + block_size)
                else:
                    # Compressed: LZW block with comp_size at header+8
                    comp_size = struct.unpack("<I", self.data[last_header + 8 : last_header + 12])[
                        0
                    ]
                    if 0 < comp_size < MAX_COMPRESSED_SIZE:
                        return align_to(last_header + 12 + comp_size)

        return None

    def _is_marker_block(self, pos: int) -> bool:
        """Check if position contains a marker block (h0=144, h1=0).

        Marker blocks indicate deferred data - the file's data is stored
        elsewhere (at the end of a region or in a shifted index).
        """
        if pos + 8 > len(self.data):
            return False
        h0, h1 = struct.unpack("<2I", self.data[pos : pos + 8])
        return bool(h0 == HEADER_SIZE and h1 == 0)

    def _find_marker_file_data(
        self, entry: DirEntry, prev_header: int, all_entries: list[DirEntry]
    ) -> int | None:
        """Find the data position for a file with a marker block.

        Marker files have their data stored in a "shifted" location:
        - Simple pattern: data is at the next sibling's prev_header position
        - Multi-block pattern: data is at the next file's multi-block index
        - End-of-region pattern: data is after all sibling files in the same tree

        Returns the block position where data should be extracted from.
        """
        file_entries = [e for e in all_entries if e.is_file]

        # Pattern 1: Next sibling's prev_header (simple single-block markers)
        # Find siblings in the same directory, sorted by entry offset
        siblings = sorted(
            [e for e in file_entries if e.parent_path == entry.parent_path],
            key=lambda e: e.offset,
        )
        for i, sib in enumerate(siblings):
            if sib.offset == entry.offset and i + 1 < len(siblings):
                next_sib = siblings[i + 1]
                if next_sib.data_offset != 0x410:  # Not first-in-block
                    next_prev = next_sib.data_offset - 4
                    # Check if it's a simple LZW block (not marker, not multi-block index)
                    if not self._is_marker_block(next_prev) and self._check_lzw_magic(
                        next_prev + 12
                    ):
                        return next_prev
                break

        # Pattern 2 & 3: Original logic for multi-block and end-of-region
        sorted_entries = sorted(file_entries, key=lambda e: e.data_offset)

        # Find our position in the sorted list
        our_idx = None
        for i, e in enumerate(sorted_entries):
            if e.offset == entry.offset:
                our_idx = i
                break

        if our_idx is None:
            return None

        # Multi-block files (>32KB) use the shifted index pattern:
        # Their data is stored at the next file's multi-block index position
        if entry.size > LZW_BLOCK_SIZE:
            for i in range(our_idx + 1, len(sorted_entries)):
                next_entry = sorted_entries[i]
                if next_entry.data_offset == 0x410:
                    continue  # Skip first-in-block files

                next_prev_header = next_entry.data_offset - 4
                if next_prev_header < 0:
                    continue

                # Check if this is a valid index position (not a marker)
                if not self._is_marker_block(next_prev_header):
                    is_multi, _ = self._is_multiblock_index(next_prev_header)
                    if is_multi:
                        return next_prev_header

        # Single-block markers: data is at the end of files that come AFTER
        # this marker in data_offset order, within the same directory tree
        our_parent = entry.parent_path
        our_data_offset = entry.data_offset

        if our_parent:
            # Include files in same directory or subdirectories,
            # but only those with data_offset > ours (come after in logical order)
            tree_files = [
                e
                for e in file_entries
                if (e.parent_path == our_parent or e.parent_path.startswith(our_parent + "/"))
                and e.data_offset > our_data_offset
            ]
            # If no files in tree, fall back to all files (marker points to empty dirs)
            if not tree_files:
                tree_files = file_entries
        else:
            # Root level marker: data is at the very END of all archive data
            # Include ALL files (including first-in-block) to find the true end
            tree_files = file_entries

        last_end = 0
        for e in tree_files:
            # Determine block position based on data_offset type
            if e.data_offset == 0x410:
                # First-in-block: position is entry.offset + data_offset
                block_pos = e.offset + e.data_offset
            else:
                ep = e.data_offset - 4
                if self._is_marker_block(ep):
                    continue
                maybe_block_pos = self._skip_past_block(ep)
                if maybe_block_pos is None:
                    continue
                block_pos = maybe_block_pos

            # Find end of this file's block
            if self._check_lzw_magic(block_pos + 12):
                comp_size = struct.unpack("<I", self.data[block_pos + 8 : block_pos + 12])[0]
                end = align_to(block_pos + 12 + comp_size)
            else:
                h0, h1 = struct.unpack("<2I", self.data[block_pos : block_pos + 8])
                is_multi, table = self._is_multiblock_index(block_pos)
                if is_multi and table:
                    offsets = self._read_multiblock_offsets(block_pos, table)
                    if offsets:
                        last_header = max(offsets)
                        if self._is_uncompressed_multiblock(block_pos):
                            # Uncompressed: header value is total block size
                            block_size = struct.unpack(
                                "<I", self.data[last_header : last_header + 4]
                            )[0]
                            end = align_to(last_header + block_size)
                        else:
                            # Compressed: LZW block
                            comp_size = struct.unpack(
                                "<I", self.data[last_header + 8 : last_header + 12]
                            )[0]
                            end = align_to(last_header + 12 + comp_size)
                    else:
                        continue
                elif h1 > 0 and h1 < 1_000_000:
                    end = align_to(block_pos + 8 + h1)
                else:
                    continue

            if end > last_end:
                last_end = end

        if last_end == 0:
            return None

        # Special case: if last_end points to a marker block, the actual data
        # is at the archive end. This happens for the "last" marker file
        # (highest data_offset) when its data is stored after all other files.
        if self._is_marker_block(last_end):
            # Find the LZW block at the archive end by scanning backward
            # in 16-byte steps (blocks are 16-byte aligned)
            archive_end = len(self.data)
            target_size = entry.size
            for offset in range(16, 512, 16):  # Check up to 512 bytes from end
                pos = archive_end - offset
                if pos < 0:
                    break
                if self._check_lzw_magic(pos + 12):
                    h1 = struct.unpack("<I", self.data[pos + 4 : pos + 8])[0]
                    _, size_field = parse_h1_field(h1)
                    if size_field == target_size:
                        return pos
            # No matching LZW block found at archive end
            return None

        return last_end

    def read_file_data(self, entry: DirEntry, all_entries: list[DirEntry] | None = None) -> bytes:
        """Read and decompress file data for an entry.

        Supports three storage formats:
        1. LZW compressed: 12-byte header + LZW data (magic 1F 9D at header+12)
        2. Uncompressed: 8-byte header + raw data (h1 = file size)
        3. Multi-block: index table with offsets to multiple LZW blocks
        4. Marker block: data stored at end of region (requires all_entries)

        For files after the first in a block sequence:
        - data_offset points to prev_block_header + 4
        - Our data starts after skipping past the previous block

        Raises TBAFSExtractionError if data cannot be located or decompressed.
        """
        if not entry.is_file:
            raise ValueError("Entry is not a file")

        target_size = entry.size

        # Determine our block position
        # data_offset = 0x410 means first file in block (relative offset)
        if entry.data_offset == 0x410:
            block_pos = entry.offset + entry.data_offset
        else:
            # data_offset points to previous block's header + 4
            prev_header = entry.data_offset - 4
            if prev_header < 0 or prev_header + 8 > len(self.data):
                raise TBAFSExtractionError(
                    f"Invalid prev header 0x{prev_header:x} for {entry.full_path}"
                )

            # Check if this is a marker block (deferred data storage)
            if self._is_marker_block(prev_header):
                if all_entries is None:
                    raise TBAFSExtractionError(
                        f"Marker file {entry.full_path} requires all_entries for extraction"
                    )
                maybe_pos = self._find_marker_file_data(entry, prev_header, all_entries)
                if maybe_pos is None:
                    raise TBAFSExtractionError(
                        f"Cannot find data for marker file {entry.full_path}"
                    )
                block_pos = maybe_pos
            else:
                maybe_pos = self._skip_past_block(prev_header)
                if maybe_pos is None:
                    raise TBAFSExtractionError(
                        f"Cannot skip past block at 0x{prev_header:x} for {entry.full_path}"
                    )
                block_pos = maybe_pos

        if block_pos + 8 > len(self.data):
            raise TBAFSExtractionError(
                f"Block position 0x{block_pos:x} out of range for {entry.full_path}"
            )

        # Check block type at our position
        # 1. Single-block LZW
        if self._check_lzw_magic(block_pos + 12):
            return self._read_blocks_from(block_pos, target_size)

        # 2. Uncompressed (h1 matches target size)
        h0, h1 = struct.unpack("<2I", self.data[block_pos : block_pos + 8])
        if h1 == target_size:
            return self._read_uncompressed_data(block_pos + 8, target_size)

        # 3. Multi-block index
        is_multi, _ = self._is_multiblock_index(block_pos)
        if is_multi:
            return self._extract_multiblock(block_pos, target_size)

        raise TBAFSExtractionError(
            f"Unknown block format at 0x{block_pos:x} for {entry.full_path} "
            f"(h0={h0}, h1={h1}, target={target_size})"
        )

    def list_files(self, verbose: bool = False) -> None:
        """List all files in the archive."""
        for entry in self.iter_entries():
            if entry.is_file:
                ft = entry.filetype_name
                comp = "C" if entry.is_compressed else " "
                if verbose:
                    print(f"{entry.size:8} {ft:8} {comp} {entry.full_path}")
                else:
                    print(entry.full_path)
            elif entry.is_directory and verbose:
                print(f"{'<DIR>':8} {'':8}   {entry.full_path}/")

    def extract_all(self, output_dir: Path) -> None:
        """Extract all files to the output directory."""
        # Collect all entries first (needed for marker file extraction)
        all_entries = list(self.iter_entries())

        for entry in all_entries:
            if entry.is_directory:
                # Create directory
                dir_path = output_dir / entry.full_path
                dir_path.mkdir(parents=True, exist_ok=True)
                print(f"Created: {entry.full_path}/")
            elif entry.is_file:
                # Extract file with RISC OS filetype suffix (e.g., "filename,feb")
                ft = entry.filetype
                assert ft is not None, f"Missing filetype for {entry.full_path}"
                file_path = output_dir / f"{entry.full_path},{ft:03x}"
                file_path.parent.mkdir(parents=True, exist_ok=True)

                try:
                    data = self.read_file_data(entry, all_entries)
                    file_path.write_bytes(data)
                    print(f"Extracted: {entry.full_path},{ft:03x} ({len(data)} bytes)")
                except (TBAFSExtractionError, ValueError, struct.error) as e:
                    print(f"Error extracting {entry.full_path}: {e}", file=sys.stderr)

    def extract_to_adfs(self, output_file: Path) -> None:
        """Extract all files to an ADFS disc image."""
        from adfs import ADFSImage

        image = ADFSImage(disc_name="TBAFS")

        # Collect all entries first (needed for marker file extraction)
        all_entries = list(self.iter_entries())

        for entry in all_entries:
            if entry.is_directory:
                image.add_directory(entry.full_path)
                print(f"Created: {entry.full_path}/")
            elif entry.is_file:
                try:
                    data = self.read_file_data(entry, all_entries)
                    image.add_file(
                        entry.full_path,
                        data,
                        entry.load_addr,
                        entry.exec_addr,
                    )
                    print(f"Added: {entry.full_path} ({len(data)} bytes)")
                except (TBAFSExtractionError, ValueError, struct.error) as e:
                    print(f"Error adding {entry.full_path}: {e}", file=sys.stderr)

        image.write(output_file)
        print(f"\nWrote ADFS image: {output_file} ({output_file.stat().st_size} bytes)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TBAFS Archive Extractor for RISC OS .b21 archives"
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # List command
    list_parser = subparsers.add_parser("list", aliases=["l"], help="List archive contents")
    list_parser.add_argument("archive", help="Path to .b21 archive")
    list_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show sizes and filetypes"
    )

    # Extract command
    extract_parser = subparsers.add_parser(
        "extract", aliases=["x"], help="Extract archive contents"
    )
    extract_parser.add_argument("archive", help="Path to .b21 archive")
    extract_parser.add_argument("-o", "--output", default=".", help="Output directory")
    extract_parser.add_argument(
        "--adfs",
        metavar="FILE.adf",
        help="Output to ADFS E format floppy image instead of filesystem",
    )

    # Info command
    info_parser = subparsers.add_parser("info", aliases=["i"], help="Show archive information")
    info_parser.add_argument("archive", help="Path to .b21 archive")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        with open(args.archive, "rb") as f:
            archive = TBAFSArchive(f)

            match args.command:
                case "list" | "l":
                    archive.list_files(verbose=args.verbose)
                case "extract" | "x":
                    if args.adfs:
                        archive.extract_to_adfs(Path(args.adfs))
                    else:
                        output_dir = Path(args.output)
                        output_dir.mkdir(parents=True, exist_ok=True)
                        archive.extract_all(output_dir)
                case "info" | "i":
                    print(f"Magic: {archive.header.magic}")
                    print(f"Root allocation: {archive.header.root_alloc}")
                    print(f"First entry offset: 0x{archive.header.first_entry_offset:X}")
                    print(f"Entry count: {archive.header.entry_count}")

                    # Single-pass counting
                    files, dirs = 0, 0
                    for e in archive.iter_entries():
                        files += e.is_file
                        dirs += e.is_directory
                    print(f"Files: {files}")
                    print(f"Directories: {dirs}")

    except FileNotFoundError:
        print(f"Error: File not found: {args.archive}", file=sys.stderr)
        return 1
    except (ValueError, TBAFSExtractionError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
