## binstruct — Python's `struct` module for Nimony, compiled.
##
## Format strings use Python's syntax, but they are parsed at **compile time**
## by a template plugin that emits straight-line code: no format parsing, no
## boxing and no allocation at run time, and format mistakes are compile errors.
##
## .. code-block:: nim
##   let (major, minor, len) = unpack("<HHI", buf)   # (uint16, uint16, uint32)
##   let bytes = pack(">HHI", 1, 2, 300)             # array[8, byte]
##   const n = calcsize("<HHI")                       # 8, a compile-time constant
##
## Formats must be string literals, or templates that expand to one:
##
## .. code-block:: nim
##   template HeaderFmt: untyped = "<BBBB4sHHI"
##   let h = unpack(HeaderFmt, buf)
##
## Value types
## ===========
##
## ====  =======================  ==========================================
## Code  Nim type                 Notes
## ====  =======================  ==========================================
## `x`   (no value)               pad byte
## `c`   `char`
## `b`   `int8`
## `B`   `uint8`
## `?`   `bool`
## `h`   `int16`
## `H`   `uint16`
## `i`   `int32`
## `I`   `uint32`
## `l`   `int32`, or `clong`      `clong` in Python's native `@` mode
## `L`   `uint32`, or `culong`    `culong` in Python's native `@` mode
## `q`   `int64`
## `Q`   `uint64`
## `n`   `int`                    native mode only
## `N`   `uint`                   native mode only
## `P`   `uint`                   native mode only (pointer-sized integer)
## `e`   `float32` (`float64` in  IEEE 754 binary16; packing can raise
##       `pack`)                  `OverflowError`
## `f`   `float32`
## `d`   `float64`
## `s`   `array[N, byte]`         `pack` accepts any `openArray[byte]` or
##                                string; it is truncated or zero-padded
## `p`   `string`                 Pascal string, as in Python
## ====  =======================  ==========================================
##
## `pack` arguments must have exactly these types, so `pack("<H", x)` with an
## `int` variable is a compile error. Write `uint16(x)`. Literals convert
## implicitly and are range-checked by the compiler.
##
## Python API
## ==========
##
## - `unpack(fmt, buf)`: the buffer length must equal the format size, else
##   `ValueError`. Returns a tuple, or the bare value for a one-value format.
## - `unpackFrom(fmt, buf, offset)`: `IndexError` if the record does not fit.
##   A negative offset counts from the end.
## - `pack(fmt, args...)`: returns `array[calcsize(fmt), byte]`. Cannot fail
##   unless the format contains `e`.
## - `packInto(fmt, buf, offset, args...)`: writes into a `seq[byte]`,
##   `string`, array or `var openArray[byte]`. `IndexError` if it does not fit.
## - `calcsize(fmt)`: a compile-time constant.
##
## Byte-order prefixes (`@ = < > !`) mean exactly what they mean in Python.
##
## Streams: `Reader` and `Writer`
## ==============================
##
## Wire protocols such as DCE/RPC choose the byte order per message (NDR's
## data representation label), so `Reader` and `Writer` carry a runtime
## `order`. Their formats always use standard sizes and the prefix means:
##
## - none or `@`: the stream's byte order, and every item aligned to its own
##   size relative to the stream origin (NDR alignment).
## - `=`: the stream's byte order, packed.
## - `<`, `>`, `!`: fixed byte order, packed.
##
## - `readFmt(r, fmt)` reads a record and advances; `IndexError` if too short.
## - `writeFmt(w, fmt, args...)` appends a record.
## - `patchFmt(w, fmt, pos, args...)` overwrites already-written bytes (packed; the
##   stream's order unless the format has a prefix), e.g. a length field.
##
## Errors
## ======
##
## Run-time failures are Nimony `ErrorCode`s: `ValueError` (wrong buffer size
## for `unpack`), `IndexError` (record outside the buffer), `OverflowError`
## (value too large for `e`), `OutOfMemError` (a string buffer could not be
## made writable). Everything else Python reports as `struct.error` is
## reported at compile time instead.
##
## Memory safety
## =============
##
## A `Reader` holds a raw pointer into the buffer it was created from, so the
## buffer must outlive it and must not be resized while it is in use.

import std/endians

# ---------------------------------------------------------------------------
# Byte order
# ---------------------------------------------------------------------------

type
  ByteOrder* = enum
    boLittle, boBig

const
  boNative* = (when defined(bigEndian): boBig else: boLittle)
  boNetwork* = boBig

type
  Bytes* = ptr UncheckedArray[byte]
    ## Raw view used by the generated code.

# ---------------------------------------------------------------------------
# Loads and stores (unchecked; callers check bounds once per record)
# ---------------------------------------------------------------------------

func binstructLd8*(p: Bytes; o: int): uint8 {.inline.} = p[o]

func binstructLd16*(p: Bytes; o: int; order: ByteOrder): uint16 {.inline.} =
  result = 0'u16
  if order == boLittle: littleEndian16(addr result, addr p[o])
  else: bigEndian16(addr result, addr p[o])

func binstructLd32*(p: Bytes; o: int; order: ByteOrder): uint32 {.inline.} =
  result = 0'u32
  if order == boLittle: littleEndian32(addr result, addr p[o])
  else: bigEndian32(addr result, addr p[o])

func binstructLd64*(p: Bytes; o: int; order: ByteOrder): uint64 {.inline.} =
  result = 0'u64
  if order == boLittle: littleEndian64(addr result, addr p[o])
  else: bigEndian64(addr result, addr p[o])

func binstructSt8*(p: Bytes; o: int; v: uint8) {.inline.} =
  {.cast(noSideEffect).}:
    p[o] = v

func binstructSt16*(p: Bytes; o: int; v: uint16; order: ByteOrder) {.inline.} =
  var x = v
  {.cast(noSideEffect).}:
    if order == boLittle: littleEndian16(addr p[o], addr x)
    else: bigEndian16(addr p[o], addr x)

func binstructSt32*(p: Bytes; o: int; v: uint32; order: ByteOrder) {.inline.} =
  var x = v
  {.cast(noSideEffect).}:
    if order == boLittle: littleEndian32(addr p[o], addr x)
    else: bigEndian32(addr p[o], addr x)

func binstructSt64*(p: Bytes; o: int; v: uint64; order: ByteOrder) {.inline.} =
  var x = v
  {.cast(noSideEffect).}:
    if order == boLittle: littleEndian64(addr p[o], addr x)
    else: bigEndian64(addr p[o], addr x)

# Target-sized types of Python's native '@' mode (always native byte order).

func binstructLdCLong*(p: Bytes; o: int): clong {.inline.} =
  result = clong(0)
  copyMem(addr result, addr p[o], sizeof(clong))
func binstructLdCULong*(p: Bytes; o: int): culong {.inline.} =
  result = culong(0)
  copyMem(addr result, addr p[o], sizeof(culong))
func binstructLdInt*(p: Bytes; o: int): int {.inline.} =
  result = 0
  copyMem(addr result, addr p[o], sizeof(int))
func binstructLdUInt*(p: Bytes; o: int): uint {.inline.} =
  result = 0'u
  copyMem(addr result, addr p[o], sizeof(uint))

func binstructStCLong*(p: Bytes; o: int; v: clong) {.inline.} =
  var x = v
  {.cast(noSideEffect).}: copyMem(addr p[o], addr x, sizeof(clong))
func binstructStCULong*(p: Bytes; o: int; v: culong) {.inline.} =
  var x = v
  {.cast(noSideEffect).}: copyMem(addr p[o], addr x, sizeof(culong))
func binstructStInt*(p: Bytes; o: int; v: int) {.inline.} =
  var x = v
  {.cast(noSideEffect).}: copyMem(addr p[o], addr x, sizeof(int))
func binstructStUInt*(p: Bytes; o: int; v: uint) {.inline.} =
  var x = v
  {.cast(noSideEffect).}: copyMem(addr p[o], addr x, sizeof(uint))

# ---------------------------------------------------------------------------
# Typed value gates: these fix the exact Nim type each format code accepts
# in `pack`/`write` and turn it into raw bits.
# ---------------------------------------------------------------------------

func binstructI8*(v: int8): uint8 {.inline.} = cast[uint8](v)
func binstructU8*(v: uint8): uint8 {.inline.} = v
func binstructBool*(v: bool): uint8 {.inline.} = (if v: 1'u8 else: 0'u8)
func binstructChar*(v: char): uint8 {.inline.} = uint8(ord(v))
func binstructI16*(v: int16): uint16 {.inline.} = cast[uint16](v)
func binstructU16*(v: uint16): uint16 {.inline.} = v
func binstructI32*(v: int32): uint32 {.inline.} = cast[uint32](v)
func binstructU32*(v: uint32): uint32 {.inline.} = v
func binstructI64*(v: int64): uint64 {.inline.} = cast[uint64](v)
func binstructU64*(v: uint64): uint64 {.inline.} = v
func binstructF32*(v: float32): uint32 {.inline.} = cast[uint32](v)
func binstructF64*(v: float64): uint64 {.inline.} = cast[uint64](v)

# ---------------------------------------------------------------------------
# IEEE 754 binary16 ('e')
# ---------------------------------------------------------------------------

func binstructHalf*(x: float64): uint16 {.raises.} =
  ## float64 -> binary16 bits with round-half-to-even, exactly like CPython.
  ## Raises `OverflowError` for finite values too large for binary16.
  let bits = cast[uint64](x)
  let sign = uint16((bits shr 63) and 1'u64) shl 15
  let exp = int((bits shr 52) and 0x7ff'u64)
  let frac = bits and 0x000f_ffff_ffff_ffff'u64
  if exp == 0x7ff:
    if frac != 0'u64: return sign or 0x7e00'u16   # NaN
    return sign or 0x7c00'u16                     # infinity
  if exp == 0:
    return sign                                   # zero / float64 subnormal
  var e = exp - 1023
  let m = frac or (1'u64 shl 52)
  if e >= -14:
    var h = m shr 42
    let rest = m and ((1'u64 shl 42) - 1'u64)
    let half = 1'u64 shl 41
    if rest > half or (rest == half and (h and 1'u64) == 1'u64): inc h
    if h == (1'u64 shl 11):
      h = h shr 1
      inc e
    if e > 15: raise OverflowError
    result = sign or (uint16(e + 15) shl 10) or uint16(h and 0x3ff'u64)
  else:
    let shift = 28 - e
    if shift >= 64: return sign
    var h = m shr uint64(shift)
    let rest = m and ((1'u64 shl uint64(shift)) - 1'u64)
    let half = 1'u64 shl uint64(shift - 1)
    if rest > half or (rest == half and (h and 1'u64) == 1'u64): inc h
    result = sign or uint16(h)

func pow2(k: int): float64 {.inline.} =
  cast[float64](uint64(k + 1023) shl 52)

func binstructHalfToF32*(h: uint16): float32 =
  ## binary16 bits -> float32 (every binary16 value is exact in float32).
  let neg = (h and 0x8000'u16) != 0'u16
  let e = int((h shr 10) and 0x1f'u16)
  let f = int(h and 0x3ff'u16)
  var r = 0.0
  if e == 0x1f:
    r = (if f != 0: NaN else: Inf)
  elif e == 0:
    r = float64(f) * pow2(-24)
  else:
    r = float64(f + 1024) * pow2(e - 25)
  if neg: r = -r
  result = float32(r)

# ---------------------------------------------------------------------------
# Byte strings ('s' and 'p')
# ---------------------------------------------------------------------------

func binstructLdBytes*[N: static int](p: Bytes; o: int): array[N, byte] =
  result = default(array[N, byte])
  for i in 0 ..< N: result[i] = p[o + i]

func binstructLdPascal*(p: Bytes; o, n: int): string =
  var k = 0
  if n > 0:
    k = int(p[o])
    if k >= n: k = n - 1
  result = newString(k)
  for i in 0 ..< k: result[i] = char(p[o + 1 + i])

func binstructStBytes*(p: Bytes; o, n: int; data: openArray[byte]) =
  let k = min(n, data.len)
  for i in 0 ..< k: binstructSt8(p, o + i, data[i])

func binstructStBytes*(p: Bytes; o, n: int; data: openArray[char]) =
  let k = min(n, data.len)
  for i in 0 ..< k: binstructSt8(p, o + i, uint8(ord(data[i])))

func binstructStPascal*(p: Bytes; o, n: int; data: openArray[byte]) =
  if n > 0:
    let k = min(min(data.len, n - 1), 255)
    binstructSt8(p, o, uint8(k))
    for i in 0 ..< k: binstructSt8(p, o + 1 + i, data[i])

func binstructStPascal*(p: Bytes; o, n: int; data: openArray[char]) =
  if n > 0:
    let k = min(min(data.len, n - 1), 255)
    binstructSt8(p, o, uint8(k))
    for i in 0 ..< k: binstructSt8(p, o + 1 + i, uint8(ord(data[i])))

func binstructZero*(p: Bytes; n: int) =
  for i in 0 ..< n: binstructSt8(p, i, 0'u8)

# ---------------------------------------------------------------------------
# Spans: one bounds check per record, then unchecked access
# ---------------------------------------------------------------------------

func binstructAlignUp*(x, a: int): int {.inline.} =
  ## Rounds `x` up to a multiple of `a` (a > 0).
  result = x
  let r = x mod a
  if r != 0: result = x + (a - r)

func binstructSpanExact*(b: openArray[byte]; n: int): Bytes {.inline, raises.} =
  if b.len != n or n == 0: raise ValueError
  result = cast[Bytes](addr b[0])

func binstructSpanExact*(b: openArray[char]; n: int): Bytes {.inline, raises.} =
  if b.len != n or n == 0: raise ValueError
  result = cast[Bytes](addr b[0])

func binstructCheckLen*(b: openArray[byte]; n: int) {.raises.} =
  if b.len != n: raise ValueError
func binstructCheckLen*(b: openArray[char]; n: int) {.raises.} =
  if b.len != n: raise ValueError

func resolveOffset(len, offset, n: int): int {.inline, raises.} =
  var off = offset
  if off < 0:
    if off + len < 0: raise IndexError
    off += len
  if n > len - off or n == 0: raise IndexError
  result = off

func binstructSpanAt*(b: openArray[byte]; offset, n: int): Bytes {.inline, raises.} =
  let off = resolveOffset(b.len, offset, n)
  result = cast[Bytes](addr b[off])

func binstructSpanAt*(b: openArray[char]; offset, n: int): Bytes {.inline, raises.} =
  let off = resolveOffset(b.len, offset, n)
  result = cast[Bytes](addr b[off])

func binstructSpanMut*(b: var openArray[byte]; offset, n: int): Bytes {.raises.} =
  let off = resolveOffset(b.len, offset, n)
  result = cast[Bytes](addr b[off])
  binstructZero(result, n)

func binstructSpanMut*(b: var seq[byte]; offset, n: int): Bytes {.raises.} =
  let off = resolveOffset(b.len, offset, n)
  result = cast[Bytes](addr b[off])
  binstructZero(result, n)

func binstructSpanMut*(b: var string; offset, n: int): Bytes {.raises.} =
  ## Strings are copy-on-write with an inline cache, so writes go through
  ## `beginStore`; the generated code calls `binstructCommit` afterwards.
  let off = resolveOffset(b.len, offset, n)
  let raw = beginStore(b, b.len, off)   # keeps the length; points at b[off]
  if raw == nil: raise OutOfMemError
  result = cast[Bytes](raw)
  binstructZero(result, n)

func binstructCommit*(b: var string) {.inline.} = endStore(b)
func binstructCommit*(b: var seq[byte]) {.inline.} = discard
func binstructCommit*(b: var openArray[byte]) {.inline.} = discard

func binstructPtrOf*[N: static int](a: var array[N, byte]): Bytes {.inline.} =
  result = cast[Bytes](addr a)

# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

type
  Reader* = object
    ## A cursor over a byte buffer. Holds a raw pointer: the buffer must
    ## outlive the reader and must not be resized while it is in use.
    data: Bytes
    len: int
    pos*: int          ## current position
    base*: int         ## stream origin used for alignment
    order*: ByteOrder  ## byte order for formats without an explicit prefix

var emptyBuf: array[1, byte]

proc initReader*(buf: openArray[byte]; order = boLittle): Reader =
  if buf.len == 0:
    result = Reader(data: cast[Bytes](addr emptyBuf), len: 0, pos: 0, base: 0,
                    order: order)
  else:
    result = Reader(data: cast[Bytes](addr buf[0]), len: buf.len, pos: 0,
                    base: 0, order: order)

proc initReader*(buf: openArray[char]; order = boLittle): Reader =
  if buf.len == 0:
    result = Reader(data: cast[Bytes](addr emptyBuf), len: 0, pos: 0, base: 0,
                    order: order)
  else:
    result = Reader(data: cast[Bytes](addr buf[0]), len: buf.len, pos: 0,
                    base: 0, order: order)

func len*(r: Reader): int {.inline.} = r.len
func remaining*(r: Reader): int {.inline.} = r.len - r.pos
func atEnd*(r: Reader): bool {.inline.} = r.pos >= r.len

func binstructTake*(r: var Reader; n: int): Bytes {.inline, raises.} =
  if n < 0 or n > r.len - r.pos: raise IndexError
  result = cast[Bytes](cast[uint](r.data) + uint(r.pos))
  r.pos += n

func binstructTakeAligned*(r: var Reader; n, a: int): Bytes {.raises.} =
  let p = r.base + binstructAlignUp(r.pos - r.base, a)
  if p > r.len: raise IndexError
  r.pos = p
  result = binstructTake(r, n)

func align*(r: var Reader; a: int) {.raises.} =
  ## Skips padding so `r.pos - r.base` is a multiple of `a`.
  discard binstructTakeAligned(r, 0, a)

func skip*(r: var Reader; n: int) {.raises.} =
  discard binstructTake(r, n)

func readBytes*(r: var Reader; n: int): seq[byte] {.raises.} =
  let p = binstructTake(r, n)
  result = newSeq[byte](n)
  for i in 0 ..< n: result[i] = p[i]

func sub*(r: var Reader; n: int): Reader {.raises.} =
  ## A reader over the next `n` bytes (advancing `r` past them). It keeps the
  ## byte order, and its alignment origin stays the one of `r`.
  let start = r.pos
  let p = binstructTake(r, n)
  result = Reader(data: cast[Bytes](cast[uint](p) - uint(start)),
                  len: start + n, pos: start, base: r.base, order: r.order)

# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

type
  Writer* = object
    data*: seq[byte]   ## everything written so far
    base*: int         ## stream origin used for alignment
    order*: ByteOrder  ## byte order for formats without an explicit prefix

func initWriter*(order = boLittle): Writer =
  Writer(data: @[], base: 0, order: order)

func len*(w: Writer): int {.inline.} = w.data.len
func pos*(w: Writer): int {.inline.} = w.data.len

func binstructReserve*(w: var Writer; n: int): Bytes =
  let start = w.data.len
  w.data.grow(start + n, 0'u8)
  result = cast[Bytes](addr w.data[start])

func binstructReserveAligned*(w: var Writer; n, a: int): Bytes =
  let target = w.base + binstructAlignUp(w.data.len - w.base, a)
  w.data.grow(target, 0'u8)
  result = binstructReserve(w, n)

func align*(w: var Writer; a: int) =
  ## Appends zero padding so `w.len - w.base` is a multiple of `a`.
  let target = w.base + binstructAlignUp(w.data.len - w.base, a)
  w.data.grow(target, 0'u8)

func writeBytes*(w: var Writer; data: openArray[byte]) =
  for b in data: w.data.add b

func writeBytes*(w: var Writer; data: openArray[char]) =
  for c in data: w.data.add uint8(ord(c))

func binstructPatchSpan*(w: var Writer; pos, n: int): Bytes {.raises.} =
  if pos < 0 or n > w.data.len - pos or n == 0: raise IndexError
  result = cast[Bytes](addr w.data[pos])

# ---------------------------------------------------------------------------
# The compile-time front end
# ---------------------------------------------------------------------------

template unpack*(fmt: string; buf: untyped): untyped {.plugin: "binstruct/structgen".}
  ## Unpacks `buf`, whose length must equal `calcsize(fmt)` (else
  ## `ValueError`). Returns a tuple, or the value itself for one-value formats.

template unpackFrom*(fmt: string; buf, offset: untyped): untyped {.plugin: "binstruct/structgen".}
  ## Unpacks the record at `offset` (negative counts from the end) of `buf`.

template pack*(fmt: string; args: varargs[untyped]): untyped {.plugin: "binstruct/structgen".}
  ## Packs `args` into an `array[calcsize(fmt), byte]`.

template packInto*(fmt: string; buf, offset: untyped; args: varargs[untyped]) {.plugin: "binstruct/structgen".}
  ## Packs `args` into `buf` at `offset`. `buf` is evaluated more than once,
  ## so pass a variable.

template calcsize*(fmt: string): untyped {.plugin: "binstruct/structgen".}
  ## The byte size of `fmt`, as a compile-time constant.

template readFmt*(r: untyped; fmt: string): untyped {.plugin: "binstruct/structgen".}
  ## Reads one record from Reader `r` and advances it.

template writeFmt*(w: untyped; fmt: string; args: varargs[untyped]) {.plugin: "binstruct/structgen".}
  ## Appends one record to Writer `w`.

template patchFmt*(w: untyped; fmt: string; pos: untyped; args: varargs[untyped]) {.plugin: "binstruct/structgen".}
  ## Overwrites bytes of Writer `w` starting at `pos` (packed layout).
