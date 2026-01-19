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
from dataclasses import dataclass
from typing import BinaryIO, Iterator
from pathlib import Path

# Archive structure constants
TBAFS_MAGIC = b"TAFS"
HEADER_SIZE = 0x90              # 144 bytes - main TBAFS header
ROOT_DIR_RESERVED = 0x80        # 128 bytes - reserved block after header
ROOT_ENTRIES_OFFSET = HEADER_SIZE + ROOT_DIR_RESERVED  # 0x110
ENTRY_SIZE = 0x40               # 64 bytes per directory entry
BLOCK_ALIGNMENT = 16            # Entries/blocks aligned to 16 bytes
LZW_BLOCK_SIZE = 32768          # 32KB decompressed blocks for large files

# LZW compression constants
LZW_MAGIC = b"\x1f\x9d"
LZW_MAX_BITS = 12
LZW_CLEAR_CODE = 256
LZW_INITIAL_BITS = 9

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


def _create_initial_dictionary() -> dict[int, bytes]:
    """Create initial LZW dictionary with single-byte codes 0-255."""
    return {i: bytes([i]) for i in range(256)}


class TBAFSExtractionError(Exception):
    """Raised when file data cannot be extracted."""
    pass


# Pre-compiled struct formats for header and entry parsing
HEADER_STRUCT = struct.Struct("<4I")  # root_alloc, unknown1, dir_header_size, reserved
ENTRY_STRUCT = struct.Struct("<6I")   # data_offset, type, load, exec, size, flags


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
    offset: int          # Position of this entry in file
    data_offset: int     # Offset to data (for files) or subdir block (for dirs)
    entry_type: int      # 1=file, 2=directory, 0xFFFFFFFF=end
    load_addr: int       # RISC OS load address (contains filetype)
    exec_addr: int       # RISC OS exec address (timestamp)
    size: int            # Uncompressed size (0 for directories)
    flags: int           # Compression flags (3 = Squash compressed)
    name: str            # Filename
    parent_path: str     # Path to parent directory

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
        if block_mode:
            next_code = LZW_CLEAR_CODE + 1  # 256 is clear code
        else:
            next_code = LZW_CLEAR_CODE

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
        self._block_index: dict[int, tuple[int, int]] | None = None

    def _parse_header(self) -> TBAFSHeader:
        """Parse the TBAFS header."""
        if len(self.data) < 32:
            raise ValueError("File too small for TBAFS header")

        magic = self.data[0:4]
        if magic != TBAFS_MAGIC:
            raise ValueError(f"Invalid magic: {magic!r}, expected {TBAFS_MAGIC!r}")

        root_alloc, unknown1, dir_header_size, _ = HEADER_STRUCT.unpack(
            self.data[4:20]
        )
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

        entry_data = self.data[offset:offset + ENTRY_SIZE]

        data_offset, entry_type, load_addr, exec_addr, size, flags = (
            ENTRY_STRUCT.unpack(entry_data[:24])
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
        if (entry.load_addr >> 20) != 0xFFF:
            return False
        return True

    def _find_all_entries_in_range(self, start: int, end: int, parent_path: str = "") -> list[DirEntry]:
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

            if self._is_valid_entry(entry):
                entries.append(entry)
                pos += ENTRY_SIZE  # Move past this 64-byte entry
            else:
                pos += BLOCK_ALIGNMENT  # Scan at 16-byte intervals

        return entries

    def _collect_all_directories(self, start_offset: int) -> list[tuple[int, str]]:
        """
        Collect ALL directory entries in the archive with a global scan.

        Returns list of (data_offset, full_path) for each directory.
        This is used to establish global boundaries for scanning.
        """
        directories = []

        # First, get root-level entries
        offset = start_offset
        while offset < len(self.data):
            entry = self._parse_entry(offset, "")
            if entry is None or entry.is_end:
                break
            if self._is_valid_entry(entry) and entry.is_directory:
                directories.append((entry.data_offset, entry.name))
            offset += ENTRY_SIZE

        # Now recursively find subdirectories within each top-level directory
        # We'll scan all directory ranges
        found_dirs = list(directories)  # Start with top-level dirs
        processed: set[int] = set()

        while found_dirs:
            data_offset, path = found_dirs.pop(0)
            if data_offset in processed:
                continue
            processed.add(data_offset)

            # Scan from this directory's offset to end of file
            # We'll find more subdirectories here
            pos = align_to(data_offset)
            while pos < len(self.data) - ENTRY_SIZE:
                entry = self._parse_entry(pos, path)

                if entry and entry.entry_type == ENTRY_TYPE_END:
                    pos += BLOCK_ALIGNMENT
                    continue

                if self._is_valid_entry(entry):
                    if entry.is_directory:
                        full_path = f"{path}/{entry.name}" if path else entry.name
                        directories.append((entry.data_offset, full_path))
                        found_dirs.append((entry.data_offset, full_path))
                    pos += ENTRY_SIZE
                else:
                    pos += BLOCK_ALIGNMENT

        return directories

    def iter_entries(self, dir_offset: int | None = None, parent_path: str = "",
                     global_boundaries: list[int] | None = None) -> Iterator[DirEntry]:
        """Iterate over all directory entries, recursively."""
        if dir_offset is None:
            # Root directory: entries start at dir_header_size + ROOT_DIR_RESERVED
            start_offset = self.header.dir_header_size + ROOT_DIR_RESERVED

            # First pass: collect ALL directories globally to establish boundaries
            all_dirs = self._collect_all_directories(start_offset)
            all_dir_offsets = sorted(set(d[0] for d in all_dirs))
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
                    yield from self.iter_entries(entry.data_offset, entry.full_path, all_dir_offsets)
        else:
            # For subdirectories, use global boundaries to find our scan range
            start = dir_offset

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
                    yield from self.iter_entries(entry.data_offset, entry.full_path, global_boundaries)

    def _build_block_index(self) -> dict[int, tuple[int, int]]:
        """
        Build an index of LZW blocks mapping decompressed size to block location.

        Returns a dict mapping decompressed_size -> (header_offset, compressed_size)
        """
        blocks: dict[int, tuple[int, int]] = {}
        pos = 0
        while True:
            pos = self.data.find(LZW_MAGIC, pos)
            if pos == -1:
                break

            header_start = pos - 12
            if header_start >= 0:
                comp_size = struct.unpack("<I", self.data[header_start + 8:header_start + 12])[0]
                if 0 < comp_size < 500000:  # Sanity check
                    compressed_data = self.data[pos:pos + comp_size]
                    try:
                        decompressed = self.decompressor.decompress(compressed_data)
                        actual_size = len(decompressed)
                        # Store by size (may have collisions, but first match wins)
                        if actual_size not in blocks:
                            blocks[actual_size] = (header_start, comp_size)
                    except Exception:
                        pass
            pos += 1
        return blocks

    def _read_blocks_from(self, start_offset: int, target_size: int) -> bytes:
        """
        Read consecutive LZW blocks starting from an offset until target_size bytes.

        Large files are split into 32KB blocks. This reads and concatenates them.
        """
        result = bytearray()
        block = start_offset

        while len(result) < target_size and block + 14 <= len(self.data):
            # Check for LZW magic
            if self.data[block + 12:block + 14] != LZW_MAGIC:
                break

            comp_size = struct.unpack("<I", self.data[block + 8:block + 12])[0]
            if comp_size == 0 or comp_size > 500000:
                break

            lzw_start = block + 12
            compressed_data = self.data[lzw_start:lzw_start + comp_size]

            try:
                decompressed = self.decompressor.decompress(compressed_data)
                result.extend(decompressed)
            except Exception:
                break

            # Next block is aligned after this one
            end = block + 12 + comp_size
            block = align_to(end)

        # Trim to exact size
        return bytes(result[:target_size])

    def read_file_data(self, entry: DirEntry) -> bytes:
        """Read and decompress file data for an entry."""
        if not entry.is_file:
            raise ValueError("Entry is not a file")

        target_size = entry.size

        # Primary method: data_offset - 4 points to block header
        header_offset = entry.data_offset - 4
        if header_offset >= 0 and header_offset + 14 <= len(self.data):
            if self.data[header_offset + 12:header_offset + 14] == LZW_MAGIC:
                result = self._read_blocks_from(header_offset, target_size)
                if len(result) == target_size:
                    return result

        # Fallback: build block index and match by size
        if self._block_index is None:
            self._block_index = self._build_block_index()

        if target_size in self._block_index:
            header_offset, _ = self._block_index[target_size]
            result = self._read_blocks_from(header_offset, target_size)
            if len(result) == target_size:
                del self._block_index[target_size]
                return result

        # Last resort: scan for matching decompressed size
        pos = 0
        while True:
            pos = self.data.find(LZW_MAGIC, pos)
            if pos == -1:
                break
            header = pos - 12
            if header >= 0:
                result = self._read_blocks_from(header, target_size)
                if len(result) == target_size:
                    return result
            pos += 1

        raise TBAFSExtractionError(f"Could not locate data for {entry.full_path}")

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
        for entry in self.iter_entries():
            if entry.is_directory:
                # Create directory
                dir_path = output_dir / entry.full_path
                dir_path.mkdir(parents=True, exist_ok=True)
                print(f"Created: {entry.full_path}/")
            elif entry.is_file:
                # Extract file
                file_path = output_dir / entry.full_path
                file_path.parent.mkdir(parents=True, exist_ok=True)

                try:
                    data = self.read_file_data(entry)
                    file_path.write_bytes(data)
                    print(f"Extracted: {entry.full_path} ({len(data)} bytes)")
                except Exception as e:
                    print(f"Error extracting {entry.full_path}: {e}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TBAFS Archive Extractor for RISC OS .b21 archives"
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # List command
    list_parser = subparsers.add_parser("list", aliases=["l"], help="List archive contents")
    list_parser.add_argument("archive", help="Path to .b21 archive")
    list_parser.add_argument("-v", "--verbose", action="store_true", help="Show sizes and filetypes")

    # Extract command
    extract_parser = subparsers.add_parser("extract", aliases=["x"], help="Extract archive contents")
    extract_parser.add_argument("archive", help="Path to .b21 archive")
    extract_parser.add_argument("-o", "--output", default=".", help="Output directory")

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
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
