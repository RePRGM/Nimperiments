## Template plugin behind `binstruct`'s `unpack`, `pack`, `read`, ...
##
## It runs at compile time: it parses the format literal (see `fmtparse`),
## writes the specialised code as Nim source, parses that with `nimparser`, and
## splices the caller's argument trees in place of `binstructArgN`
## placeholders. Every format error becomes a compile error at the literal.

import plugins, nimparser
import fmtparse

const ArgPrefix = "binstructArg"

# ---------------------------------------------------------------------------
# Per-code snippets
# ---------------------------------------------------------------------------

func isNativeSized(it: FmtItem): bool = it.size == 0

func binstructAlignUpCT(x, a: int): int =
  result = x
  if a > 0 and x mod a != 0: result = x + (a - x mod a)

func replaceTotal(s, total: string): string =
  ## Replaces the `TOTAL` marker in a span-call template.
  result = ""
  var i = 0
  while i < s.len:
    if i + 5 <= s.len and s[i] == 'T' and s[i+1] == 'O' and s[i+2] == 'T' and
        s[i+3] == 'A' and s[i+4] == 'L':
      result.add total
      i += 5
    else:
      result.add s[i]
      inc i

func startsWithPrefix(t, prefix: string): bool =
  if t.len <= prefix.len: return false
  for i in 0 ..< prefix.len:
    if t[i] != prefix[i]: return false
  result = true

func valueType(it: FmtItem): string =
  ## The exact Nim type a value of this item has.
  case it.code
  of 'b': "int8"
  of 'B': "uint8"
  of '?': "bool"
  of 'c': "char"
  of 'h': "int16"
  of 'H': "uint16"
  of 'i': "int32"
  of 'I': "uint32"
  of 'l': (if isNativeSized(it): "clong" else: "int32")
  of 'L': (if isNativeSized(it): "culong" else: "uint32")
  of 'q': "int64"
  of 'Q': "uint64"
  of 'n': "int"
  of 'N', 'P': "uint"
  of 'e': "float64"        # packing rounds from float64, as CPython does
  of 'f': "float32"
  of 'd': "float64"
  else: ""                 # 's' / 'p' take any openArray

func loadExpr(it: FmtItem; p, o, ord: string): string =
  let pos = p & ", " & o
  case it.code
  of 'b': "cast[int8](binstructLd8(" & pos & "))"
  of 'B': "binstructLd8(" & pos & ")"
  of '?': "(binstructLd8(" & pos & ") != 0'u8)"
  of 'c': "char(binstructLd8(" & pos & "))"
  of 'h': "cast[int16](binstructLd16(" & pos & ", " & ord & "))"
  of 'H': "binstructLd16(" & pos & ", " & ord & ")"
  of 'i': "cast[int32](binstructLd32(" & pos & ", " & ord & "))"
  of 'I': "binstructLd32(" & pos & ", " & ord & ")"
  of 'l':
    if isNativeSized(it): "binstructLdCLong(" & pos & ")"
    else: "cast[int32](binstructLd32(" & pos & ", " & ord & "))"
  of 'L':
    if isNativeSized(it): "binstructLdCULong(" & pos & ")"
    else: "binstructLd32(" & pos & ", " & ord & ")"
  of 'q': "cast[int64](binstructLd64(" & pos & ", " & ord & "))"
  of 'Q': "binstructLd64(" & pos & ", " & ord & ")"
  of 'n': "binstructLdInt(" & pos & ")"
  of 'N', 'P': "binstructLdUInt(" & pos & ")"
  of 'e': "binstructHalfToF32(binstructLd16(" & pos & ", " & ord & "))"
  of 'f': "cast[float32](binstructLd32(" & pos & ", " & ord & "))"
  of 'd': "cast[float64](binstructLd64(" & pos & ", " & ord & "))"
  of 's':
    if it.n == 0: "default(array[0, byte])"
    else: "binstructLdBytes[" & $it.n & "](" & pos & ")"
  of 'p':
    if it.n == 0: "\"\""
    else: "binstructLdPascal(" & pos & ", " & $it.n & ")"
  else: ""

func storeStmt(it: FmtItem; p, o, ord, v: string): string =
  let pos = p & ", " & o
  case it.code
  of 'b': "binstructSt8(" & pos & ", binstructI8(" & v & "))"
  of 'B': "binstructSt8(" & pos & ", binstructU8(" & v & "))"
  of '?': "binstructSt8(" & pos & ", binstructBool(" & v & "))"
  of 'c': "binstructSt8(" & pos & ", binstructChar(" & v & "))"
  of 'h': "binstructSt16(" & pos & ", binstructI16(" & v & "), " & ord & ")"
  of 'H': "binstructSt16(" & pos & ", binstructU16(" & v & "), " & ord & ")"
  of 'i': "binstructSt32(" & pos & ", binstructI32(" & v & "), " & ord & ")"
  of 'I': "binstructSt32(" & pos & ", binstructU32(" & v & "), " & ord & ")"
  of 'l':
    if isNativeSized(it): "binstructStCLong(" & pos & ", " & v & ")"
    else: "binstructSt32(" & pos & ", binstructI32(" & v & "), " & ord & ")"
  of 'L':
    if isNativeSized(it): "binstructStCULong(" & pos & ", " & v & ")"
    else: "binstructSt32(" & pos & ", binstructU32(" & v & "), " & ord & ")"
  of 'q': "binstructSt64(" & pos & ", binstructI64(" & v & "), " & ord & ")"
  of 'Q': "binstructSt64(" & pos & ", binstructU64(" & v & "), " & ord & ")"
  of 'n': "binstructStInt(" & pos & ", " & v & ")"
  of 'N', 'P': "binstructStUInt(" & pos & ", " & v & ")"
  of 'e': "binstructSt16(" & pos & ", binstructHalf(" & v & "), " & ord & ")"
  of 'f': "binstructSt32(" & pos & ", binstructF32(" & v & "), " & ord & ")"
  of 'd': "binstructSt64(" & pos & ", binstructF64(" & v & "), " & ord & ")"
  of 's': "binstructStBytes(" & pos & ", " & $it.n & ", " & v & ")"
  of 'p': "binstructStPascal(" & pos & ", " & $it.n & ", " & v & ")"
  else: "discard"

func orderExpr(lay: Layout; stream: string): string =
  case lay.order
  of okNative: "boNative"
  of okLittle: "boLittle"
  of okBig: "boBig"
  of okRuntime: stream & ".order"

func byteSpan(it: FmtItem): string =
  ## Bytes an item occupies (zero-count alignment items occupy none).
  if it.code in {'s', 'p', 'x'}: $it.n
  elif not it.hasValue: "0"
  else: it.sizeExpr

func byteSpanNum(it: FmtItem): int =
  if it.code in {'s', 'p', 'x'}: it.n
  elif not it.hasValue: 0
  else: it.size

# ---------------------------------------------------------------------------
# Static layout: offsets known at compile time
# ---------------------------------------------------------------------------

type
  StaticLayout = object
    decls: string           ## `const` lines for target-dependent offsets
    offsets: seq[string]    ## offset expression of each item
    total: string
    totalNum: int           ## -1 if the size is target dependent

proc staticLayout(lay: Layout): StaticLayout =
  result = StaticLayout(decls: "", offsets: @[], total: "0", totalNum: 0)
  var known = true
  var cur = 0
  var curExpr = "0"
  for k in 0 ..< lay.items.len:
    let it = lay.items[k]
    let alignable = lay.aligned and it.code notin {'s', 'p', 'x'}
    if known and not isNativeSized(it):
      if alignable: cur = binstructAlignUpCT(cur, it.size)
      result.offsets.add $cur
      cur += byteSpanNum(it)
    else:
      if known:
        known = false
        curExpr = $cur
      if alignable:
        result.decls.add "  const binstructO" & $k & " = binstructAlignUp(" &
          curExpr & ", " & it.sizeExpr & ")\n"
        curExpr = "binstructO" & $k
      result.offsets.add curExpr
      result.decls.add "  const binstructE" & $k & " = " & curExpr & " + " &
        byteSpan(it) & "\n"
      curExpr = "binstructE" & $k
  if known:
    result.total = $cur
    result.totalNum = cur
  else:
    result.total = curExpr
    result.totalNum = -1

# ---------------------------------------------------------------------------
# Code generation
# ---------------------------------------------------------------------------

func arg(k: int): string = ArgPrefix & $k

proc valueNames(lay: Layout): seq[string] =
  result = @[]
  for k in 0 ..< lay.items.len:
    if lay.items[k].hasValue: result.add "binstructV" & $k

proc resultExpr(names: seq[string]): string =
  if names.len == 1: return names[0]
  result = "("
  for i in 0 ..< names.len:
    if i > 0: result.add ", "
    result.add names[i]
  result.add ")"

proc genUnpack(lay: Layout; spanCall: string; asExpr: var bool): string =
  ## `spanCall` is the span constructor, with `TOTAL` for the size.
  let sl = staticLayout(lay)
  let ord = orderExpr(lay, "")
  var body = sl.decls
  if sl.totalNum != 0:
    body.add "  let binstructP = " & replaceTotal(spanCall, sl.total) & "\n"
  for k in 0 ..< lay.items.len:
    let it = lay.items[k]
    if it.hasValue:
      body.add "  let binstructV" & $k & " = " &
        loadExpr(it, "binstructP", sl.offsets[k], ord) & "\n"
  let names = valueNames(lay)
  if names.len == 0:
    asExpr = false
    result = "block:\n" & body & "  discard\n"
  else:
    asExpr = true
    result = "(block:\n" & body & "  " & resultExpr(names) & ")"

proc typedLets(lay: Layout; firstArg: int; body: var string): seq[string] =
  ## Evaluates the caller's values left to right, each converted to the exact
  ## type of its format code. Returns the expression to store for each item.
  result = @[]
  var a = firstArg
  for k in 0 ..< lay.items.len:
    let it = lay.items[k]
    if it.hasValue:
      let t = valueType(it)
      if t.len > 0:
        body.add "  let binstructA" & $k & ": " & t & " = " & arg(a) & "\n"
        result.add "binstructA" & $k
      else:
        result.add arg(a)              # 's' / 'p': any openArray, used in place
      inc a
    else:
      result.add ""

proc genStores(lay: Layout; sl: StaticLayout; vals: seq[string]; ord: string;
               body: var string) =
  for k in 0 ..< lay.items.len:
    let it = lay.items[k]
    if it.hasValue:
      body.add "  " & storeStmt(it, "binstructP", sl.offsets[k], ord, vals[k]) & "\n"

proc genPack(lay: Layout): string =
  let sl = staticLayout(lay)
  var body = sl.decls
  let vals = typedLets(lay, 0, body)
  body.add "  var binstructR = default(array[" & sl.total & ", byte])\n"
  if sl.totalNum != 0:
    body.add "  let binstructP = binstructPtrOf(binstructR)\n"
    genStores(lay, sl, vals, orderExpr(lay, ""), body)
  result = "(block:\n" & body & "  binstructR)"

proc genPackInto(lay: Layout): string =
  let sl = staticLayout(lay)
  var body = sl.decls
  let vals = typedLets(lay, 2, body)
  if sl.totalNum != 0:
    body.add "  let binstructP = binstructSpanMut(" & arg(0) & ", " & arg(1) &
      ", " & sl.total & ")\n"
    genStores(lay, sl, vals, orderExpr(lay, ""), body)
    body.add "  binstructCommit(" & arg(0) & ")\n"
  result = "block:\n" & body & "  discard\n"

proc genRead(lay: Layout; asExpr: var bool): string =
  let r = arg(0)
  let ord = orderExpr(lay, r)
  var body = ""
  if lay.aligned:
    for k in 0 ..< lay.items.len:
      let it = lay.items[k]
      let a = (if it.code in {'s', 'p', 'x'}: 1 else: it.size)
      let take = "binstructTakeAligned(" & r & ", " & byteSpan(it) & ", " & $a & ")"
      if it.hasValue:
        body.add "  let binstructV" & $k & " = " & loadExpr(it, take, "0", ord) & "\n"
      else:
        body.add "  discard " & take & "\n"
  else:
    let sl = staticLayout(lay)
    if sl.totalNum != 0:
      body.add "  let binstructP = binstructTake(" & r & ", " & sl.total & ")\n"
    for k in 0 ..< lay.items.len:
      let it = lay.items[k]
      if it.hasValue:
        body.add "  let binstructV" & $k & " = " &
          loadExpr(it, "binstructP", sl.offsets[k], ord) & "\n"
  let names = valueNames(lay)
  if names.len == 0:
    asExpr = false
    result = "block:\n" & body & "  discard\n"
  else:
    asExpr = true
    result = "(block:\n" & body & "  " & resultExpr(names) & ")"

proc genWrite(lay: Layout): string =
  let w = arg(0)
  let ord = orderExpr(lay, w)
  var body = ""
  let vals = typedLets(lay, 1, body)     # evaluate values before touching `w`
  if lay.aligned:
    for k in 0 ..< lay.items.len:
      let it = lay.items[k]
      let a = (if it.code in {'s', 'p', 'x'}: 1 else: it.size)
      let res = "binstructReserveAligned(" & w & ", " & byteSpan(it) & ", " & $a & ")"
      if it.hasValue:
        body.add "  " & storeStmt(it, res, "0", ord, vals[k]) & "\n"
      else:
        body.add "  discard " & res & "\n"
  else:
    let sl = staticLayout(lay)
    if sl.totalNum != 0:
      body.add "  let binstructP = binstructReserve(" & w & ", " & sl.total & ")\n"
      genStores(lay, sl, vals, ord, body)
  result = "block:\n" & body & "  discard\n"

proc genPatch(lay: Layout): string =
  var lay = lay
  lay.aligned = false                    # absolute position: packed layout
  let w = arg(0)
  let sl = staticLayout(lay)
  var body = ""
  let vals = typedLets(lay, 2, body)
  if sl.totalNum != 0:
    body.add "  let binstructP = binstructPatchSpan(" & w & ", " & arg(1) &
      ", " & sl.total & ")\n"
    genStores(lay, sl, vals, orderExpr(lay, w), body)
  result = "block:\n" & body & "  discard\n"

# ---------------------------------------------------------------------------
# Plugin entry
# ---------------------------------------------------------------------------

proc substitute(r: var Replacer; args: seq[NifCursor]) =
  ## Copies the generated tree, replacing `binstructArgN` identifiers by the
  ## caller's argument trees (a balanced `replace`, so nothing is dropped).
  if r.isAtom:
    if r.kind == Ident and startsWithPrefix(r.identText, ArgPrefix):
      let t = r.identText
      var idx = 0
      for i in ArgPrefix.len ..< t.len: idx = idx * 10 + (ord(t[i]) - ord('0'))
      replace r, Any, args[idx]
    else:
      keep r, Any
  else:
    loopKeepTag r:
      substitute(r, args)

proc tr(input: NifCursor): NifBuilder =
  let nameCur = firstChild(input)
  let name = (if nameCur.kind == Symbol: symBasename(nameCur.symId)
              else: identText(nameCur))
  var c = callArgs(input)
  # collect all arguments; the format is the 1st, or the 2nd for stream calls
  var all: seq[NifCursor] = @[]
  while c.hasMore:
    all.add c
    skip c
  let fmtIdx = (if name in ["readFmt", "writeFmt", "patchFmt"]: 1 else: 0)
  if all.len <= fmtIdx:
    return errorTree("binstruct: missing format string", input)
  var lit = all[fmtIdx]
  if lit.kind == TagLit: lit = firstChild(lit)
  if lit.kind != StrLit:
    return errorTree("binstruct: the format must be a string literal, or a " &
      "template that expands to one (a `const` is not supported)", all[fmtIdx])
  let fmt = stringValue(lit)
  var args: seq[NifCursor] = @[]
  for i in 0 ..< all.len:
    if i != fmtIdx: args.add all[i]

  let mode = (if name in ["readFmt", "writeFmt", "patchFmt"]: fmStream else: fmPython)
  let lay = parseFormat(fmt, mode)
  if lay.error.len > 0:
    return errorTree("binstruct: " & lay.error, all[fmtIdx])

  # arity: fixed leading arguments, then one per value for the packers
  let fixed = (case name
               of "unpack": 1
               of "unpackFrom": 2
               of "pack": 0
               of "packInto": 2
               of "calcsize": 0
               of "readFmt": 1
               of "writeFmt": 1
               of "patchFmt": 2
               else: -1)
  if fixed < 0:
    return errorTree("binstruct: unknown operation " & name, input)
  let wantValues = name in ["pack", "packInto", "writeFmt", "patchFmt"]
  let expected = fixed + (if wantValues: lay.nvalues else: 0)
  if args.len != expected:
    if wantValues:
      return errorTree("binstruct: format '" & fmt & "' takes " & $lay.nvalues &
        " value(s), got " & $(args.len - fixed), all[fmtIdx])
    return errorTree("binstruct: wrong number of arguments", input)

  var asExpr = true
  var code = ""
  case name
  of "unpack":
    code = genUnpack(lay, "binstructSpanExact(" & arg(0) & ", TOTAL)", asExpr)
    if staticLayout(lay).totalNum == 0:
      # empty record: only the length check remains
      code = "block:\n  binstructCheckLen(" & arg(0) & ", 0)\n  discard\n"
      asExpr = false
      if lay.nvalues > 0:
        var names = valueNames(lay)
        var body = ""
        for k in 0 ..< lay.items.len:
          if lay.items[k].hasValue:
            body.add "  let binstructV" & $k & " = " &
              loadExpr(lay.items[k], "nil", "0", "boNative") & "\n"
        code = "(block:\n  binstructCheckLen(" & arg(0) & ", 0)\n" & body &
          "  " & resultExpr(names) & ")"
        asExpr = true
  of "unpackFrom":
    code = genUnpack(lay, "binstructSpanAt(" & arg(0) & ", " & arg(1) & ", TOTAL)", asExpr)
  of "pack": code = genPack(lay)
  of "packInto":
    code = genPackInto(lay)
    asExpr = false
  of "calcsize":
    let sl = staticLayout(lay)
    code = (if sl.decls.len == 0: sl.total
            else: "(block:\n" & sl.decls & "  " & sl.total & ")")
  of "readFmt": code = genRead(lay, asExpr)
  of "writeFmt":
    code = genWrite(lay)
    asExpr = false
  of "patchFmt":
    code = genPatch(lay)
    asExpr = false
  else: discard

  let parsed = (if asExpr: parseExpr(code, lit.info) else: parseStmt(code, lit.info))
  var r = Replacer(dest: createTree())
  setCursor(r, parsed)
  substitute(r, args)
  result = r.dest

saveTree tr(loadPluginInput())
