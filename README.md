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

To extract with `,xxx` suffixes on filenames, use:

```bash
python3 tbafs.py extract samples/Blurp.b21 -o output/ --types
```

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
<DIR>               !Blurp/
     275 Obey     C !Blurp/!Boot
     589 Obey     C !Blurp/!Run
  174260 Absolute C !Blurp/!RunImage
    3868 Sprite   C !Blurp/!Sprites
     441 005      C !Blurp/GameCols
<DIR>               !Blurp/Graphics/
   11297 UnkData  C !Blurp/Graphics/Aura
...
```

The `C` indicates the file is compressed.

## Format Documentation

See [FORMAT.md](FORMAT.md) for the complete file format specification.

Key features:
- Magic number: `TAFS`
- Compression: 12-bit LZW (Unix compress compatible)
- Large files split into 32KB blocks
- RISC OS filetype and timestamp preservation

## Limitations

- Extraction only (cannot create archives)
- RISC OS timestamps in archives are not preserved on extraction

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
