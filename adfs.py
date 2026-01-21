"""
ADFS Floppy Disc Image Creator

Creates ADFS E format (800KB) floppy disc images compatible with
RISC OS emulators like RPCEmu, Arculator, and MiSTER Archie.

ADFS E format:
- 800KB capacity (819200 bytes)
- 1024-byte logical sectors
- 5 sectors/track, 80 tracks, 2 heads (interleaved)
- New map format (1 zone, duplicated)
- NewDir format directories ("Nick" signature)
- No boot block (floppies only)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

# ADFS E format constants
E_FORMAT_SIZE = 800 * 1024  # 819200 bytes
E_SECTOR_SIZE = 1024
E_LOG2_SECTOR_SIZE = 10
E_SECS_PER_TRACK = 5
E_HEADS = 2
E_TRACKS = 80
E_DENSITY = 2  # Double density

# E format specific parameters (from RISC OS PRM)
E_NZONES = 1  # Single allocation zone covers entire disc
E_IDLEN = 15  # Fragment ID width in bits (allows 32767 fragments)
E_LOG2_BPMB = 7  # log2(128) - each map bit represents 128 bytes
E_BPMB = 128  # Bytes per map bit (minimum allocation unit)
E_ZONE_SPARE = 0x520  # 1312 spare bits at end of zone for header overhead
E_ROOTFRAG = 0x00000203  # Root directory: fragment 2, sector offset 3

# Key offsets for E format (no boot block on floppies!)
MAP_OFFSET = 0x000  # Map zone 0 at sector 0
MAP_COPY_OFFSET = 0x400  # Map zone 0 copy at sector 1
ROOT_OFFSET = 0x800  # Root directory at sector 2

# Directory constants (NewDir format)
NEWDIR_SIZE = 2048  # 2KB = 2 sectors
NEWDIR_MAX_ENTRIES = 77
NEWDIR_ENTRY_SIZE = 26
NEWDIR_TAIL_OFFSET = 0x7D7  # 2007 = 2048 - 41

# File attributes
ATTR_OWNER_READ = 0x01
ATTR_OWNER_WRITE = 0x02
# Bit 0x08 has dual meaning: LOCKED for files, DIRECTORY flag for directory entries
ATTR_LOCKED = 0x08
ATTR_DIRECTORY = 0x08
DEFAULT_ATTRIBS = ATTR_OWNER_READ | ATTR_OWNER_WRITE


def calculate_zone_check(data: bytes) -> int:
    """
    Calculate zone checksum using the RISC OS algorithm.

    The algorithm processes 4 bytes at a time from the end of the zone,
    accumulating with carries between the 4 accumulators.
    """
    sum0 = sum1 = sum2 = sum3 = 0

    # Process from end to start, 4 bytes at a time (excluding byte 0 which is the check)
    pos = len(data) - 4
    while pos > 0:
        sum0 += data[pos + 0] + (sum3 >> 8)
        sum3 &= 0xFF
        sum1 += data[pos + 1] + (sum0 >> 8)
        sum0 &= 0xFF
        sum2 += data[pos + 2] + (sum1 >> 8)
        sum1 &= 0xFF
        sum3 += data[pos + 3] + (sum2 >> 8)
        sum2 &= 0xFF
        pos -= 4

    # Final step: don't add byte 0 (the check byte itself)
    sum0 += sum3 >> 8
    sum1 += data[1] + (sum0 >> 8)
    sum2 += data[2] + (sum1 >> 8)
    sum3 += data[3] + (sum2 >> 8)

    return (sum0 ^ sum1 ^ sum2 ^ sum3) & 0xFF


def calculate_dir_checksum(data: bytes) -> int:
    """
    Calculate NewDir checksum using Linux kernel algorithm.

    The algorithm (from Linux fs/adfs/dir_f.c):
    1. Process header as words, scanning for entries (26 bytes each)
    2. Process 36 bytes (9 words) of tail starting at offset 2008
       (the lastmark byte at 2007 is NOT included)
    3. Compress 32-bit result to 8-bit by XORing all 4 bytes
    """

    def ror13(val: int) -> int:
        """Rotate right 32-bit value by 13 bits."""
        return ((val >> 13) | (val << 19)) & 0xFFFFFFFF

    dircheck = 0

    # Part 1: Process header and entries
    # For each potential entry, process words up to word-aligned boundary
    # Entry positions: 5, 31, 57, ... (26 bytes apart)
    # Continue while the first byte of entry area is non-zero
    last = 5 - 26  # Will become 5 on first iteration
    i = 0

    while True:
        last += 26
        # Process words while i < (last & ~3)
        while i < (last & ~3):
            word = struct.unpack("<I", data[i : i + 4])[0]
            dircheck = word ^ ror13(dircheck)
            i += 4

        # Check if we've reached the end (byte at 'last' is zero)
        if last >= len(data) or data[last] == 0:
            break

    # Process remaining bytes from i to last
    while i < last:
        dircheck = data[i] ^ ror13(dircheck)
        i += 1

    # Part 2: Process tail starting at byte 2008 (NOT 2007!)
    # 36 bytes = 9 words
    for j in range(9):
        word = struct.unpack("<I", data[2008 + j * 4 : 2008 + j * 4 + 4])[0]
        dircheck = word ^ ror13(dircheck)

    # Compress 32-bit to 8-bit
    checksum = (dircheck ^ (dircheck >> 8) ^ (dircheck >> 16) ^ (dircheck >> 24)) & 0xFF
    return checksum


@dataclass
class ADFSDirEntry:
    """A single directory entry (26 bytes in NewDir format)."""

    name: str
    load_addr: int
    exec_addr: int
    length: int
    indirect_addr: int  # Fragment ID << 8 | sector offset
    attribs: int = DEFAULT_ATTRIBS

    def to_bytes(self) -> bytes:
        """Serialize to 26-byte entry."""
        entry = bytearray(26)

        # Name: up to 10 chars, CR terminator if < 10 chars (NewDir format)
        name_bytes = self.name.encode("latin-1")[:10]
        for i, b in enumerate(name_bytes):
            entry[i] = b
        if len(name_bytes) < 10:
            entry[len(name_bytes)] = 0x0D  # CR terminator

        # Load address (4 bytes LE)
        struct.pack_into("<I", entry, 10, self.load_addr)

        # Exec address (4 bytes LE)
        struct.pack_into("<I", entry, 14, self.exec_addr)

        # Length (4 bytes LE)
        struct.pack_into("<I", entry, 18, self.length)

        # Indirect disc address (3 bytes LE) + new attributes (1 byte)
        entry[22] = self.indirect_addr & 0xFF
        entry[23] = (self.indirect_addr >> 8) & 0xFF
        entry[24] = (self.indirect_addr >> 16) & 0xFF
        entry[25] = self.attribs

        return bytes(entry)


@dataclass
class ADFSDirectory:
    """
    NewDir format directory (2048 bytes, "Nick" signature).

    Structure:
    - Byte 0: Master sequence number
    - Bytes 1-4: "Nick" (start marker)
    - Bytes 5-2006: Up to 77 entries (26 bytes each)
    - Bytes 2007-2047: Tail (41 bytes)
    """

    name: str = "$"
    parent_addr: int = 0
    entries: list[ADFSDirEntry] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        """Serialize to 2048-byte NewDir directory."""
        data = bytearray(NEWDIR_SIZE)

        # Header
        data[0] = 0  # Master sequence number
        data[1:5] = b"Nick"  # Start identifier

        # Entries start at offset 5, sorted by name (case-insensitive)
        offset = 5
        for entry in sorted(self.entries, key=lambda e: e.name.upper()):
            entry_bytes = entry.to_bytes()
            data[offset : offset + 26] = entry_bytes
            offset += 26

        # Tail at offset 0x7D7 (2007)
        tail = NEWDIR_TAIL_OFFSET

        # Tail structure for NewDir:
        # +0x00: last mark (0)
        # +0x01-0x02: reserved
        # +0x03-0x05: parent indirect address (3 bytes)
        # +0x06-0x18: directory title (19 bytes, space padded)
        # +0x19-0x22: directory name (10 bytes, last char top bit set)
        # +0x23: end sequence number (must match start)
        # +0x24-0x27: "Nick" (end identifier)
        # +0x28: checksum

        data[tail] = 0  # Last mark

        # Parent address (3 bytes)
        data[tail + 0x03] = self.parent_addr & 0xFF
        data[tail + 0x04] = (self.parent_addr >> 8) & 0xFF
        data[tail + 0x05] = (self.parent_addr >> 16) & 0xFF

        # Directory title (19 bytes, CR terminated, null padded)
        title_bytes = self.name.encode("latin-1")[:18] + b"\x0d"
        data[tail + 0x06 : tail + 0x06 + len(title_bytes)] = title_bytes
        # Rest is already zero from bytearray init

        # Directory name (10 bytes, CR terminated)
        name_bytes = self.name.encode("latin-1")[:9]
        for i, b in enumerate(name_bytes):
            data[tail + 0x19 + i] = b
        # CR terminator (no top bit - that's only for entry names)
        data[tail + 0x19 + len(name_bytes)] = 0x0D

        # End sequence (must match start at byte 0)
        data[tail + 0x23] = data[0]

        # End identifier "Nick"
        data[tail + 0x24 : tail + 0x28] = b"Nick"

        # Checksum (XOR of all bytes except last)
        data[NEWDIR_SIZE - 1] = calculate_dir_checksum(data)

        return bytes(data)


class ADFSImage:
    """
    Creates ADFS E format (800KB) floppy disc images.

    E format layout:
    - Sector 0 (0x000): Map zone 0 with disc record
    - Sector 1 (0x400): Map zone 0 copy
    - Sectors 2-3 (0x800): Root directory (2048 bytes)
    - Sectors 4+: File data
    """

    def __init__(self, size: int = E_FORMAT_SIZE, disc_name: str = "TBAFS"):
        self.size = size
        self.data = bytearray(size)
        self.disc_name = disc_name

        # Allocation tracking
        # Files get fragment IDs starting from 3 (2 is system object)
        self._next_frag_id = 3
        # Data starts after root directory
        self._next_data_offset = ROOT_OFFSET + NEWDIR_SIZE

        # Directory tracking
        self._directories: dict[str, ADFSDirectory] = {}
        self._dir_offsets: dict[str, int] = {"": ROOT_OFFSET}
        self._dir_entries: dict[str, list[tuple[str, int, ADFSDirEntry]]] = {"": []}

        # Track all allocations for the map bitstream
        # List of (start_offset, length) in bytes
        self._allocations: list[tuple[int, int, int]] = []  # (offset, length, frag_id)

        # System allocation: map (2 sectors) + root (2 sectors) = fragment 2
        self._allocations.append((0, E_SECTOR_SIZE * 4, 2))

    def _alloc_space(self, size: int) -> tuple[int, int]:
        """Allocate space for data, returns (fragment_id, offset)."""
        # Round up to sector boundary
        alloc_size = ((size + E_SECTOR_SIZE - 1) // E_SECTOR_SIZE) * E_SECTOR_SIZE

        # Minimum allocation must fit fragment ID + terminator in bitstream
        # Minimum units = idlen + 1 = 16, minimum bytes = 16 * 128 = 2048
        min_alloc = (E_IDLEN + 1) * E_BPMB
        if alloc_size < min_alloc:
            alloc_size = min_alloc

        if self._next_data_offset + alloc_size > self.size:
            raise ValueError(f"Disc full: cannot allocate {size} bytes")

        frag_id = self._next_frag_id
        offset = self._next_data_offset

        self._allocations.append((offset, alloc_size, frag_id))

        self._next_frag_id += 1
        self._next_data_offset += alloc_size

        return frag_id, offset

    def _get_parent_path(self, path: str) -> str:
        """Get parent directory path."""
        if "/" not in path:
            return ""
        return path.rsplit("/", 1)[0]

    def _ensure_directory(self, path: str) -> None:
        """Ensure directory exists, creating parents as needed."""
        if not path or path in self._dir_entries:
            return

        parent = self._get_parent_path(path)
        self._ensure_directory(parent)

        dir_name = path.split("/")[-1]

        # Allocate space for directory (2048 bytes)
        frag_id, offset = self._alloc_space(NEWDIR_SIZE)

        if parent not in self._dir_entries:
            self._dir_entries[parent] = []
        self._dir_entries[path] = []

        # Create directory entry for parent
        # Directory indirect address: frag_id << 8
        entry = ADFSDirEntry(
            name=dir_name,
            load_addr=0,
            exec_addr=0,
            length=0,
            indirect_addr=frag_id << 8,
            attribs=ATTR_DIRECTORY | ATTR_OWNER_READ,
        )
        self._dir_entries[parent].append((dir_name, frag_id, entry))
        self._directories[path] = ADFSDirectory(name=dir_name, parent_addr=0)
        self._dir_offsets[path] = offset

    def add_directory(self, path: str) -> None:
        """Create a directory at the given path."""
        self._ensure_directory(path)

    def add_file(self, path: str, data: bytes, load_addr: int, exec_addr: int) -> None:
        """Add a file to the image."""
        parent = self._get_parent_path(path)
        self._ensure_directory(parent)

        name = path.split("/")[-1]

        # Allocate space
        frag_id, offset = self._alloc_space(len(data))

        # Write file data
        self.data[offset : offset + len(data)] = data

        # File indirect address: frag_id << 8 (no sharing offset for simplicity)
        entry = ADFSDirEntry(
            name=name,
            load_addr=load_addr,
            exec_addr=exec_addr,
            length=len(data),
            indirect_addr=frag_id << 8,
            attribs=DEFAULT_ATTRIBS,
        )
        self._dir_entries[parent].append((name, frag_id, entry))

    def _write_map_zone(self, offset: int) -> None:
        """Write a map zone at the given offset."""
        zone = bytearray(E_SECTOR_SIZE)

        # Zone header (4 bytes):
        # Byte 0: ZoneCheck (calculated at end)
        # Bytes 1-2: FreeLink (offset to first free space, top bit set)
        # Byte 3: CrossCheck (XOR with other zones should give 0xFF)

        # Disc record at offset 4 (60 bytes) - only in zone 0
        dr = 4

        zone[dr + 0x00] = E_LOG2_SECTOR_SIZE  # log2secsize = 10
        zone[dr + 0x01] = E_SECS_PER_TRACK  # secspertrack = 5
        zone[dr + 0x02] = E_HEADS  # heads = 2
        zone[dr + 0x03] = E_DENSITY  # density = 2 (double)
        zone[dr + 0x04] = E_IDLEN  # idlen = 15
        zone[dr + 0x05] = E_LOG2_BPMB  # log2bpmb = 7
        zone[dr + 0x06] = 1  # skew = 1
        zone[dr + 0x07] = 0  # bootoption = 0
        zone[dr + 0x08] = 0  # lowsector = 0
        zone[dr + 0x09] = E_NZONES  # nzones = 1
        struct.pack_into("<H", zone, dr + 0x0A, E_ZONE_SPARE)  # zone_spare
        struct.pack_into("<I", zone, dr + 0x0C, E_ROOTFRAG)  # root
        struct.pack_into("<I", zone, dr + 0x10, E_FORMAT_SIZE)  # disc_size

        # Disc ID
        struct.pack_into("<H", zone, dr + 0x14, 0x8DC5)

        # Disc name (10 bytes, space padded)
        name_bytes = self.disc_name.encode("latin-1")[:10].ljust(10, b" ")
        zone[dr + 0x16 : dr + 0x20] = name_bytes

        # Build allocation bitstream
        # The bitstream starts after the disc record (offset 64 = 0x40)
        # Each allocation unit = bpmb bytes = 128 bytes
        # Bits represent: fragment_id (idlen bits) followed by padding 0s and a terminating 1

        # For simplicity, mark all used space as fragment 2 (system object)
        # then free space as the free chain

        # The bitstream format:
        # - Fragment ID (15 bits)
        # - Padding zeros
        # - Terminating 1 bit

        # System fragment (ID=2) covers map + root = 4 sectors = 32 alloc units
        # (4096 bytes / 128 = 32 units)

        # For now, use simplified allocation:
        # Write fragment 2 for system area, then free space fragment

        # FreeLink points to first free fragment (bit offset from byte 1)
        # For E format, typical value is 0x81F8 (top bit set + offset)

        # The zone has zone_spare bits that are not used for allocation
        # Total allocation bits = (sector_size * 8) - zone_spare = 8192 - 1312 = 6880 bits
        alloc_bits = (E_SECTOR_SIZE * 8) - E_ZONE_SPARE

        # Build the bitstream
        bitstream = bytearray((alloc_bits + 7) // 8)

        # Write fragment 2 (system: map + root)
        # Takes 32 allocation units = 32 bits of space representation
        # Format: 15-bit ID, then zeros, then 1 bit at position 31 (0-indexed)
        # ID=2 in binary: 000000000000010
        bit_pos = 0

        # Fragment 2: system object (map + root = 4096 bytes = 32 allocation units)
        frag2_units = (ROOT_OFFSET + NEWDIR_SIZE) // E_BPMB  # 32
        self._write_fragment(bitstream, bit_pos, 2, frag2_units)
        bit_pos += frag2_units

        # Write allocated fragments for files
        for _alloc_offset, alloc_len, frag_id in self._allocations:
            if frag_id == 2:
                continue  # Already handled system fragment
            units = alloc_len // E_BPMB
            # Note: _alloc_space guarantees alloc_len >= (E_IDLEN+1)*E_BPMB
            # so units will always be >= 16, no minimum enforcement needed here
            self._write_fragment(bitstream, bit_pos, frag_id, units)
            bit_pos += units

        # Remaining space is free
        free_units = (E_FORMAT_SIZE // E_BPMB) - bit_pos
        if free_units > 0:
            # Free space fragment: ID = offset to next free (0 means end of chain)
            self._write_fragment(bitstream, bit_pos, 0, free_units)

        # Copy bitstream to zone (starting at byte 64)
        zone[64 : 64 + len(bitstream)] = bitstream[: E_SECTOR_SIZE - 64]

        # FreeLink: offset in bits to first free space from byte 1
        # The first free space is at bit_pos (after all allocations)
        # But we need offset from the start of allocation area
        free_bit_offset = bit_pos + (64 * 8) - 8  # Relative to byte 1
        # Top bit of high byte is set to indicate valid free link
        zone[1] = free_bit_offset & 0xFF  # Low byte
        zone[2] = ((free_bit_offset >> 8) & 0xFF) | 0x80  # High byte with top bit set

        # CrossCheck: for single zone, must be 0xFF
        zone[3] = 0xFF

        # ZoneCheck: checksum of the zone
        zone[0] = calculate_zone_check(bytes(zone))

        # Write to image
        self.data[offset : offset + E_SECTOR_SIZE] = zone

    def _write_fragment(
        self, bitstream: bytearray, start_bit: int, frag_id: int, units: int
    ) -> None:
        """Write a fragment to the bitstream."""
        # Fragment format: ID (15 bits), padding zeros, terminating 1
        # Total length = units bits

        if units < E_IDLEN + 1:
            # Fragment too small, minimum is idlen + 1 bits
            units = E_IDLEN + 1

        # Write the fragment ID (15 bits, LSB first)
        for i in range(E_IDLEN):
            bit_val = (frag_id >> i) & 1
            byte_idx = (start_bit + i) // 8
            bit_idx = (start_bit + i) % 8
            if byte_idx < len(bitstream):
                if bit_val:
                    bitstream[byte_idx] |= 1 << bit_idx
                else:
                    bitstream[byte_idx] &= ~(1 << bit_idx)

        # Write terminating 1 bit at position (start_bit + units - 1)
        end_bit = start_bit + units - 1
        byte_idx = end_bit // 8
        bit_idx = end_bit % 8
        if byte_idx < len(bitstream):
            bitstream[byte_idx] |= 1 << bit_idx

    def _write_directories(self) -> None:
        """Write all directories to the image."""
        # Root directory - uses disc name, parent points to itself
        root_dir = ADFSDirectory(name=self.disc_name, parent_addr=E_ROOTFRAG)
        for _name, _frag_id, entry in self._dir_entries.get("", []):
            root_dir.entries.append(entry)
        self.data[ROOT_OFFSET : ROOT_OFFSET + NEWDIR_SIZE] = root_dir.to_bytes()

        # Subdirectories
        for path, directory in self._directories.items():
            if path and path in self._dir_offsets:
                for _name, _frag_id, entry in self._dir_entries.get(path, []):
                    directory.entries.append(entry)
                offset = self._dir_offsets[path]
                self.data[offset : offset + NEWDIR_SIZE] = directory.to_bytes()

    def write(self, filename: str | Path) -> None:
        """Write the disc image to a file."""
        # Write directories first (so we know all allocations)
        self._write_directories()

        # Write map zone 0
        self._write_map_zone(MAP_OFFSET)

        # Copy map to zone 1 (duplicate)
        self.data[MAP_COPY_OFFSET : MAP_COPY_OFFSET + E_SECTOR_SIZE] = self.data[
            MAP_OFFSET : MAP_OFFSET + E_SECTOR_SIZE
        ]

        # Write to file
        with open(filename, "wb") as f:
            f.write(self.data)


def create_blank_image(filename: str | Path, disc_name: str = "Blank") -> None:
    """Create a blank, formatted ADFS E disc image."""
    image = ADFSImage(disc_name=disc_name)
    image.write(filename)
