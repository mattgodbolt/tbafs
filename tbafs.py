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
ENTRY_SIZE = 0x40  # 64 bytes per directory entry

# LZW compression constants
LZW_MAGIC = b"\x1f\x9d"
LZW_MAX_BITS = 12
LZW_CLEAR_CODE = 256

# Compression types (encoded in high byte of h1 field in data block header)
COMP_TYPE_RAW = 0  # Type 0: Uncompressed/raw data
COMP_TYPE_HCT1 = 1  # Type 1: HCT1/CompMod compressed (not supported)
COMP_TYPE_SQUASH = 2  # Type 2: Squash/LZW compressed
LZW_INITIAL_BITS = 9

# Entry type constants
ENTRY_TYPE_FILE = 1
ENTRY_TYPE_DIR = 2
ENTRY_TYPE_END = 0xFFFFFFFF

# Entry scanning limits (from disassembly: cmp r4, 0x10 at 0x1b4c)
MAX_ENTRIES_PER_BLOCK = 16

# Multi-block index constants (from disassembly: 0x2094-0x20a4)
MULTIBLOCK_INDEX_SIZE = 0x110  # 272 bytes read for index
MULTIBLOCK_OFFSETS_START = 0x10  # Block offsets begin at index+0x10

# Mode byte values (from disassembly: cmp r1, 2 at 0x1fc8)
MODE_MULTIBLOCK = 2  # Mode byte == 2 means multi-block file


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


def _create_initial_dictionary() -> dict[int, bytes]:
    """Create initial LZW dictionary with single-byte codes 0-255."""
    return {i: bytes([i]) for i in range(256)}


class TBAFSExtractionError(Exception):
    """Raised when file data cannot be extracted."""

    pass


# Pre-compiled struct formats for header and entry parsing
HEADER_STRUCT = struct.Struct("<4I")  # root_alloc, unknown1, dir_header_size, reserved
# Entry structure: type(4), load(4), exec(4), size(4), flags(4) = 20 bytes at offset 0
# Name at offset 0x14 (20 bytes), data_position at offset 0x3c
ENTRY_STRUCT = struct.Struct("<5I")  # type, load, exec, size, flags


@dataclass
class TBAFSHeader:
    """TBAFS archive header."""

    magic: str
    root_alloc: int
    unknown1: int
    dir_header_size: int
    entry_table_offset: int  # Offset to first directory entry (from header[0x18])
    entry_count: int


@dataclass
class DirEntry:
    """A directory entry in a TBAFS archive."""

    offset: int  # Position of this entry in file
    entry_type: int  # 1=file, 2=directory, 0xFFFFFFFF=end (at entry[0x00])
    load_addr: int  # RISC OS load address (contains filetype) (at entry[0x04])
    exec_addr: int  # RISC OS exec address (timestamp) (at entry[0x08])
    size: int  # Uncompressed size (0 for directories) (at entry[0x0c])
    flags: int  # Attributes (at entry[0x10])
    name: str  # Filename (at entry[0x14], 32 bytes max)
    data_position: int  # Disk position for file data (at entry[0x3c])
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
            if block_mode and code == LZW_CLEAR_CODE:
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

    def _parse_header(self) -> TBAFSHeader:
        """Parse the TBAFS header."""
        if len(self.data) < 32:
            raise ValueError("File too small for TBAFS header")

        magic = self.data[0:4]
        if magic != TBAFS_MAGIC:
            raise ValueError(f"Invalid magic: {magic!r}, expected {TBAFS_MAGIC!r}")

        root_alloc, unknown1, dir_header_size, _ = HEADER_STRUCT.unpack(self.data[4:20])
        entry_table_offset, entry_count = struct.unpack("<II", self.data[24:32])

        return TBAFSHeader(
            magic=magic.decode("ascii"),
            root_alloc=root_alloc,
            unknown1=unknown1,
            dir_header_size=dir_header_size,
            entry_table_offset=entry_table_offset,
            entry_count=entry_count,
        )

    def _parse_entry(self, offset: int, parent_path: str = "") -> DirEntry | None:
        """Parse a single directory entry at the given offset.

        Entry structure (64 bytes):
        - 0x00: type (4 bytes) - 1=file, 2=dir, 0xFFFFFFFF=end
        - 0x04: load_addr (4 bytes) - RISC OS load address
        - 0x08: exec_addr (4 bytes) - RISC OS exec address
        - 0x0c: size (4 bytes) - uncompressed file size
        - 0x10: flags (4 bytes) - attributes
        - 0x14: name (32 bytes) - null-terminated filename
        - 0x34: reserved (4 bytes)
        - 0x38: config (4 bytes) - mode byte at 0x3b
        - 0x3c: data_position (4 bytes) - disk position for reading
        """
        if offset + ENTRY_SIZE > len(self.data):
            return None

        entry_data = self.data[offset : offset + ENTRY_SIZE]

        # Parse fields from correct offsets
        entry_type, load_addr, exec_addr, size, flags = ENTRY_STRUCT.unpack(entry_data[0x00:0x14])

        # Extract null-terminated name from offset 0x14 (20 bytes)
        name_bytes = entry_data[0x14:0x28]
        null_pos = name_bytes.find(b"\x00")
        if null_pos != -1:
            name_bytes = name_bytes[:null_pos]
        name = name_bytes.decode("latin-1", errors="replace")

        # Data position at offset 0x3c
        data_position = struct.unpack("<I", entry_data[0x3C:0x40])[0]

        return DirEntry(
            offset=offset,
            entry_type=entry_type,
            load_addr=load_addr,
            exec_addr=exec_addr,
            size=size,
            flags=flags,
            name=name,
            data_position=data_position,
            parent_path=parent_path,
        )

    def _is_valid_entry(self, entry: DirEntry | None) -> bool:
        """Check if an entry is valid (not end marker or null).

        Entry validation is straightforward per disassembly - the format
        provides explicit entry counts, so we just check the entry type.
        """
        if not entry:
            return False
        return entry.entry_type in (ENTRY_TYPE_FILE, ENTRY_TYPE_DIR)

    def _get_dir_entry_blocks(self, entry: DirEntry) -> list[tuple[int, int]]:
        """
        Get all entry block positions for a directory.

        The data_position field (entry[0x3c]) points to a block table structure.
        Format:
        - +0x00-0x07: header (8 bytes)
        - +0x08: first entry block position
        - +0x0c: count of entries in first block
        - +0x10: second entry block position (if exists)
        - +0x14: count of entries in second block
        - ... continues in pairs until position is 0

        Returns list of (position, count) tuples.
        """
        block_table = entry.data_position
        blocks: list[tuple[int, int]] = []

        # Directory block header: 8-byte header, then (position, count) pairs
        # Module scans for position == 0 (0x1b14: cmp r0, 0)
        # Count field is available for index-based lookup (0x1ba8: ldm r8, {r0, r1})
        offset = 8  # Skip 8-byte header (h0=144, h1=0)
        while block_table + offset + 8 <= len(self.data):
            pos, count = struct.unpack(
                "<2I", self.data[block_table + offset : block_table + offset + 8]
            )
            if pos == 0:
                break
            blocks.append((pos, count))
            offset += 8

        return blocks

    def iter_entries(
        self,
        dir_entry: DirEntry | None = None,
        parent_path: str = "",
    ) -> Iterator[DirEntry]:
        """Iterate over all directory entries, recursively.

        Args:
            dir_entry: Directory entry to scan children of. None for root.
            parent_path: Path prefix for entries.
        """
        if dir_entry is None:
            # Root directory: entry table offset comes from header[0x18]
            start_offset = self.header.entry_table_offset

            # Collect root entries using header count, with max 16 per block safety limit
            # (from disassembly: cmp r4, 0x10 at 0x1b4c)
            root_entries = []
            offset = start_offset
            max_entries = min(self.header.entry_count, MAX_ENTRIES_PER_BLOCK)
            for _ in range(max_entries):
                if offset + ENTRY_SIZE > len(self.data):
                    break
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
                    yield from self.iter_entries(entry, entry.full_path)
        else:
            # Get all entry blocks for this directory
            entry_blocks = self._get_dir_entry_blocks(dir_entry)

            # Scan each entry block
            entries: list[DirEntry] = []
            for block_pos, count in entry_blocks:
                # Scan 'count' entries starting at block_pos
                for i in range(count):
                    offset = block_pos + i * ENTRY_SIZE
                    if offset + ENTRY_SIZE > len(self.data):
                        break
                    entry = self._parse_entry(offset, parent_path)
                    if entry is None or entry.is_end:
                        continue
                    if self._is_valid_entry(entry):
                        entries.append(entry)

            # Yield entries and recurse into subdirectories
            for entry in entries:
                yield entry
                if entry.is_directory:
                    yield from self.iter_entries(entry, entry.full_path)

    def _read_block(self, block_pos: int) -> bytes:
        """Read and decompress a single data block.

        Block header format:
        - h0: (compression_type << 24) | uncompressed_size
        - For type 2 (compressed): h1 = compressed_size, data at +8
        - For type 0 (raw): data at +4

        Returns the decompressed/raw block data.
        """
        h0 = struct.unpack("<I", self.data[block_pos : block_pos + 4])[0]
        comp_type = (h0 >> 24) & 0xFF
        uncomp_size = h0 & 0xFFFFFF

        if comp_type == COMP_TYPE_SQUASH:
            comp_size = struct.unpack("<I", self.data[block_pos + 4 : block_pos + 8])[0]
            if comp_size <= 0 or block_pos + 8 + comp_size > len(self.data):
                raise TBAFSExtractionError(
                    f"Invalid compressed size {comp_size} at 0x{block_pos:x}"
                )
            lzw_data = self.data[block_pos + 8 : block_pos + 8 + comp_size]
            return self.decompressor.decompress(lzw_data)
        elif comp_type == COMP_TYPE_RAW:
            return self.data[block_pos + 4 : block_pos + 4 + uncomp_size]
        else:
            raise TBAFSExtractionError(
                f"Unsupported compression type {comp_type} at 0x{block_pos:x}"
            )

    def read_file_data(self, entry: DirEntry) -> bytes:
        """Read and decompress file data for an entry.

        Block header format depends on compression type:

        Compressed (type=2): 8-byte header
        - h0: (0x02 << 24) | uncompressed_size
        - h1: compressed_size
        - LZW data starts at offset +8

        Raw/uncompressed (type=0): 4-byte header
        - h0: uncompressed_size (high byte is 0)
        - Raw data starts at offset +4

        For multi-block files (entry mode byte = 2):
        - entry[0x3c] points to multi-block index
        - Index has h0 = num_blocks * 256, block offsets at +0x10

        Raises TBAFSExtractionError if data cannot be located or decompressed.
        """
        if not entry.is_file:
            raise ValueError("Entry is not a file")

        target_size = entry.size
        block_pos = entry.data_position

        # Read mode byte from entry offset 0x3B (per disassembly at 0x1fc0)
        if entry.offset + 0x3B >= len(self.data):
            raise TBAFSExtractionError(
                f"Cannot read mode byte for {entry.full_path} at 0x{entry.offset:x}"
            )
        mode_byte = self.data[entry.offset + 0x3B]

        if block_pos < 0 or block_pos + 8 > len(self.data):
            raise TBAFSExtractionError(
                f"Invalid block position 0x{block_pos:x} for {entry.full_path}"
            )

        # Multi-block file (mode byte == 2, per disassembly at 0x1fc8)
        if mode_byte == MODE_MULTIBLOCK:
            return self._read_multiblock(block_pos, target_size)

        # Single block file
        return self._read_block(block_pos)[:target_size]

    def _read_multiblock(self, index_pos: int, target_size: int) -> bytes:
        """Read a multi-block file from its index.

        Multi-block index format (from disassembly at 0x2094):
        - Total size read: 272 bytes (0x110)
        - h0 byte 0: Loop counter (starts at 0)
        - h0 byte 1: Number of blocks
        - h1: Always 0
        - Bytes 4-15: Reserved (not accessed by module)
        - +0x10: Block offset table (4 bytes per block)

        The pattern h0 = num_blocks * 256 puts the block count in byte 1.
        """
        h0, h1 = struct.unpack("<2I", self.data[index_pos : index_pos + 8])

        # Validate: h1 must be 0, byte 0 of h0 is counter (should be 0 initially)
        if h1 != 0:
            raise TBAFSExtractionError(
                f"Invalid multi-block index at 0x{index_pos:x}: h1=0x{h1:x} (expected 0)"
            )
        if h0 == 0:
            raise TBAFSExtractionError(
                f"Invalid multi-block index at 0x{index_pos:x}: h0=0 (no blocks)"
            )

        # Block count is in byte 1: (h0 >> 8) & 0xFF when byte 0 is 0
        # We don't need it since the loop reads until target_size or offset 0

        result = bytearray()
        offset_pos = index_pos + MULTIBLOCK_OFFSETS_START

        while len(result) < target_size:
            if offset_pos + 4 > len(self.data):
                break

            block_offset = struct.unpack("<I", self.data[offset_pos : offset_pos + 4])[0]
            if block_offset == 0:
                break
            if block_offset >= len(self.data):
                raise TBAFSExtractionError(
                    f"Invalid block offset 0x{block_offset:x} in multi-block index"
                )

            result.extend(self._read_block(block_offset))
            offset_pos += 4

        return bytes(result[:target_size])

    def list_files(self, verbose: bool = False) -> None:
        """List all files in the archive."""
        for entry in self.iter_entries():
            if entry.is_file:
                ft = entry.filetype_name
                if verbose:
                    print(f"{entry.size:8} {ft:8} {entry.full_path}")
                else:
                    print(entry.full_path)
            elif entry.is_directory and verbose:
                print(f"{'<DIR>':8} {'':8} {entry.full_path}/")

    def extract_all(self, output_dir: Path) -> None:
        """Extract all files to the output directory."""
        for entry in self.iter_entries():
            if entry.is_directory:
                dir_path = output_dir / entry.full_path
                dir_path.mkdir(parents=True, exist_ok=True)
                print(f"Created: {entry.full_path}/")
            elif entry.is_file:
                ft = entry.filetype
                assert ft is not None, f"Missing filetype for {entry.full_path}"
                file_path = output_dir / f"{entry.full_path},{ft:03x}"
                file_path.parent.mkdir(parents=True, exist_ok=True)

                try:
                    data = self.read_file_data(entry)
                    file_path.write_bytes(data)
                    print(f"Extracted: {entry.full_path},{ft:03x} ({len(data)} bytes)")
                except (TBAFSExtractionError, ValueError, struct.error) as e:
                    print(f"Error extracting {entry.full_path}: {e}", file=sys.stderr)

    def extract_to_adfs(self, output_file: Path) -> None:
        """Extract all files to an ADFS disc image."""
        from adfs import ADFSImage

        image = ADFSImage(disc_name="TBAFS")

        for entry in self.iter_entries():
            if entry.is_directory:
                image.add_directory(entry.full_path)
                print(f"Created: {entry.full_path}/")
            elif entry.is_file:
                try:
                    data = self.read_file_data(entry)
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
                    print(f"Entry table offset: 0x{archive.header.entry_table_offset:X}")
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
