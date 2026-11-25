# binstruct

Python's `struct` module for Nimony, with the format string parsed at
**compile time**. A template plugin turns each `pack`/`unpack` call into
straight-line loads and stores: no run-time parsing, no boxing, no allocation,
and format mistakes are compile errors at the call site.

```nim
import binstruct

let (major, minor, size) = unpack("<HHI", buf)   # (uint16, uint16, uint32)
let n = unpackFrom(">I", buf, 8)                  # one value -> bare uint32
let hdr = pack(">HHI", 1, 2, 300)                 # array[8, byte]
packInto("<H", buf, 6, 0x4142)                    # seq[byte] / string / array
const sz = calcsize("<HHI")                       # 8, at compile time
```

For wire protocols with a per-message byte order (DCE/RPC `drep`, NDR):

```nim
var r = initReader(pdu)
let (vers, minor, ptype, flags, drep) = readFmt(r, "<BBBB4s")
r.order = (if (drep[0] shr 4) == 1: boLittle else: boBig)
let (fragLen, authLen, callId) = readFmt(r, "=HHI")   # stream order, packed
let (a, b, c) = readFmt(stub, "HIQ")                  # stream order, NDR-aligned

var w = initWriter(boBig)
writeFmt(w, "HIQ", flags, count, handle)
patchFmt(w, "H", 8, uint16(w.len))                    # back-patch a length
```

See `examples/dcerpc.nim` for a complete request PDU encoder/decoder, and the
doc comment at the top of `src/binstruct.nim` for the full reference.

## Layout

- `src/binstruct.nim`: runtime core (loads/stores, spans, `Reader`, `Writer`)
  and the public templates.
- `src/binstruct/structgen.nim`: the compile-time plugin (code generator).
- `src/binstruct/fmtparse.nim`: format-string parser used by the plugin.

## Requirements

A Nimony toolchain built with the native backend (`arkham` + `nifasm` from
`nim-lang/nativenif`): on Linux, macOS (arm64), Windows and FreeBSD hosts
Nimony compiles plugins with it. Programs using binstruct can target any backend.

## Tests

`tests/run.sh` runs:

- `tdiff.nim`: 220 random formats (all prefixes and codes, native `@`
  alignment, half floats, Pascal strings) checked byte-for-byte against
  CPython. Regenerate with `python3 gen_diff.py`.
- `tapi.nim`: `unpackFrom`, `packInto`, Reader/Writer, NDR alignment,
  `patchFmt`, run-time errors.
- `compile_errors/`: programs that must fail to compile, with their messages.

Pass `--native` to run on the native backend instead of C.

## Known limitations

- Formats must be string literals or templates expanding to one; a `const`
  reaches the plugin as an unresolved symbol.
- Formats are limited to 512 values; `s`/`p`/`x` to 16 MiB each.
- `packInto`, `readFmt`, `writeFmt` and `patchFmt` evaluate the buffer/stream
  argument more than once: pass a variable.
- A `Reader` holds a raw pointer; the buffer must outlive it and must not be
  resized meanwhile.
