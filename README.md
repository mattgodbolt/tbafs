# TBAFS Archive Extractor

A Python tool for extracting files from TBAFS archives (`.b21` files), a proprietary format used by RISC OS computers.

## Background

TBAFS (TBA Filing System) was created by TBA Software as a high-performance archive format for RISC OS. It features LZW compression and preserves RISC OS metadata. This tool was developed by reverse-engineering the format, as no public specification exists.

## Installation

Requires Python 3.9+. No external dependencies.

```bash
git clone https://github.com/mattgodbolt/tbafs.git
cd tbafs
```

## Usage

### List archive contents

```bash
python3 tbafs.py list samples/Blurp.b21
```

Verbose listing with sizes and filetypes:

```bash
python3 tbafs.py list -v samples/Blurp.b21
```

### Extract files

```bash
python3 tbafs.py extract samples/Blurp.b21 -o output/
```

### Extract to ADFS floppy image

Create an ADFS E format (800KB) floppy disc image loadable in RISC OS emulators:

```bash
python3 tbafs.py extract samples/Blurp.b21 --adfs blurp.adf
```

The resulting `.adf` file can be loaded directly in emulators like RPCEmu or Arculator. Files retain their original RISC OS filetypes and timestamps.

### Show archive info

```bash
python3 tbafs.py info samples/Blurp.b21
```

### Create *SetTypes script

```bash
python3 tbafs.py types samples/Blurp.b21
```


## Example Output

```
$ python3 tbafs.py list -v samples/Blurp.b21
<DIR>              20 Jul 1997 22:46:55  !Blurp/
     275 Obey      27 Jul 1994 17:50:14  !Blurp/!Boot
     534 Obey      26 Jan 1997 17:23:33  !Blurp/!Run
  174292 Absolute  01 Jan 1997 21:30:15  !Blurp/!RunImage
    3868 Sprite    01 Jul 1994 15:45:44  !Blurp/!Sprites
     441 005       27 Oct 1994 17:10:37  !Blurp/GameCols
<DIR>              20 Jul 1997 22:46:56  !Blurp/Graphics/
   11128 004       27 Nov 1996 23:39:16  !Blurp/Graphics/Aura
...
```

## Format Documentation

See [FORMAT.md](FORMAT.md) for the complete file format specification.

Key features:
- Magic number: `TAFS`
- Compression: 12-bit LZW (Unix compress compatible)
- Large files split into 32KB blocks
- RISC OS filetype and timestamp preservation

## Limitations

- Extraction only (cannot create archives)
- ADFS images are limited to 800KB (E format)

## RISC OS Filetypes

Common filetypes you may encounter:

| Code | Name | Description |
|------|------|-------------|
| FEB | Obey | Script file |
| FF8 | Absolute | Executable program |
| FF9 | Sprite | RISC OS sprite image |
| FFA | Module | RISC OS module |
| FFB | BASIC | BBC BASIC program |
| FFD | Data | Generic data |
| FFF | Text | Plain text |

Run `python3 tbafs.py list -v <archive>` to see filetypes for all files in an archive.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- TBA Software for creating the original TBAFS format
- The RISC OS community for keeping these archives accessible
- [Archive Team](http://fileformats.archiveteam.org/) for format documentation efforts
