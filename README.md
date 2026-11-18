# liquid-engine-tools

Small Python tools for studying games built on the 11 bit studios Liquid engine (tested on one x64 build).
No game files, tables or decoded data are in this repo: you run the tools on your own copy.

| tool | job |
|---|---|
| `twomidx.py <game dir> <archive> [outdir]` | list / unpack an `.idx` + `.dat` archive (entries are name hashes) |
| `exeprops.py <exe> <out.tsv>` | property registration tables (class, base, property, type, flags, offset) read from the exe: RTTI vtables of `*Property*` classes + a disassembly pass (needs `pefile`, `capstone`) |
| `twomcfg.py <tsv[,tsv]> <file.bin> <TopClass\|auto> [out.json] [--trace]` | binary config reader driven by that table; prints `OK <class> end=<pos>` when the parse lands exactly on the file end |
| `twomauto.py <tsv> <dir> <outdir>` | auto mode over a directory: finds the top class of every file |
| `twomscan.py <tsv> <dir\|file> <out.jsonl> [ClassRegex]` | pulls embedded polymorphic objects (component configs) out of entity template files |

## Format notes
- Config file: u32 payload size, then the top object.
- Object: per class level an optional marker `0dd0adde` + u32 version, then the properties in registration order.
- The base class block is stored before or after the own properties depending on the class; the reader learns the order per class (a parse must land on the next element / file end).
- Strings: `00` = empty, `01` + bytes + `00`. Arrays: u32 count + elements. Polymorphic element: class name string + object.
- A second tsv can add classes the exe does not register (`C<TAB><TAB>Class<TAB>Base` and `P<TAB>Class<TAB>Base<TAB>BASE<TAB>0`).

Python 3.13. Research use.
