## Format-string parser shared by the `binstruct` code generator.
##
## Pure Nim, no runtime dependencies: it is compiled into the compile-time
## plugin and turns a Python `struct` format string into a flat list of items
## the generator lays out.

type
  FmtMode* = enum
    fmPython   ## Python `struct` semantics (`pack`, `unpack`, `calcsize`, ...)
    fmStream   ## Reader/Writer semantics (runtime byte order, NDR alignment)

  OrderKind* = enum
    okNative   ## byte order of the compilation target
    okLittle
    okBig
    okRuntime  ## byte order stored in the Reader / Writer

  FmtItem* = object
    code*: char
    n*: int           ## byte length for 's' / 'p', pad count for 'x', else 1
    size*: int        ## byte size of the item, 0 if it is target-dependent
    sizeExpr*: string ## Nim expression for the size (always valid)
    hasValue*: bool

  Layout* = object
    order*: OrderKind
    aligned*: bool    ## natural alignment applies
    items*: seq[FmtItem]
    nvalues*: int
    error*: string    ## non-empty when the format is invalid

const
  MaxValues* = 512           ## values per format; more is almost surely a typo
  MaxBytes* = 1 shl 24       ## byte length limit for one 's' / 'p' / 'x'

func str(c: char): string =
  result = newString(1)
  result[0] = c

func standardSize(c: char): int =
  case c
  of 'x', 'c', 'b', 'B', '?', 's', 'p': 1
  of 'h', 'H', 'e': 2
  of 'i', 'I', 'l', 'L', 'f': 4
  of 'q', 'Q', 'd': 8
  else: 0

func nativeSizeExpr(c: char): string =
  ## Sizes that depend on the target in Python's '@' mode.
  case c
  of 'l': "sizeof(clong)"
  of 'L': "sizeof(culong)"
  of 'n', 'N': "sizeof(int)"
  of 'P': "sizeof(pointer)"
  else: ""

func parseFormat*(fmt: string; mode: FmtMode): Layout =
  result = Layout(order: okNative, aligned: true, items: @[], nvalues: 0,
                  error: "")
  var standard = false
  var i = 0
  if fmt.len > 0:
    case fmt[0]
    of '@': i = 1
    of '=': standard = true; result.aligned = false; i = 1
    of '<': standard = true; result.aligned = false; result.order = okLittle; i = 1
    of '>', '!': standard = true; result.aligned = false; result.order = okBig; i = 1
    else: discard
  if mode == fmStream:
    standard = true          # wire formats always use standard sizes
    if result.order == okNative: result.order = okRuntime
  while i < fmt.len:
    var c = fmt[i]
    if c in {' ', '\t', '\n', '\r', '\v', '\f'}:
      inc i
      continue
    var num = 1
    if c in {'0'..'9'}:
      num = 0
      while i < fmt.len and fmt[i] in {'0'..'9'}:
        num = num * 10 + (ord(fmt[i]) - ord('0'))
        if num > MaxBytes:
          result.error = "repeat count too large in format '" & fmt & "'"
          return
        inc i
      if i >= fmt.len:
        result.error = "repeat count given without a format code in '" & fmt & "'"
        return
      c = fmt[i]
    if c in {'@', '=', '<', '>', '!'}:
      result.error = "byte-order character '" & str(c) &
        "' is only allowed at the start of the format"
      return
    var size = standardSize(c)
    var sizeExpr = $size
    if c in {'n', 'N', 'P'}:
      if mode == fmStream:
        result.error = "format code '" & str(c) & "' is not allowed in " &
          "Reader/Writer formats (wire formats have no target-sized types)"
        return
      if standard:
        result.error = "format code '" & str(c) &
          "' is only available in native ('@') mode"
        return
      size = 0
      sizeExpr = nativeSizeExpr(c)
    elif c in {'l', 'L'} and not standard:
      size = 0
      sizeExpr = nativeSizeExpr(c)
    elif size == 0:
      result.error = "bad character '" & str(c) & "' in format '" & fmt & "'"
      return
    case c
    of 'x':
      if num > 0:
        result.items.add FmtItem(code: c, n: num, size: num, sizeExpr: $num,
                                 hasValue: false)
    of 's', 'p':
      result.items.add FmtItem(code: c, n: num, size: num, sizeExpr: $num,
                               hasValue: true)
      inc result.nvalues
    else:
      for r in 0 ..< num:
        result.items.add FmtItem(code: c, n: 1, size: size, sizeExpr: sizeExpr,
                                 hasValue: true)
        inc result.nvalues
        if result.nvalues > MaxValues:
          result.error = "format '" & fmt & "' has more than " & $MaxValues &
            " values"
          return
      if num == 0 and result.aligned:
        # Python: a zero count still aligns ("0l" pads to long alignment)
        result.items.add FmtItem(code: c, n: 0, size: size, sizeExpr: sizeExpr,
                                 hasValue: false)
    inc i
