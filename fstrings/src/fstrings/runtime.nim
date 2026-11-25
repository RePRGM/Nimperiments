## Runtime half of the f-string implementation: `fmtField` applies a Python
## format spec to one value, `fmtRepr` implements the `!r` conversion.
##
## Static specs (`{x:>8.2f}`) are validated by the plugin at compile time.
## A spec that is only known at run time (`{x:{w}}`) and turns out invalid,
## or a spec that does not fit the value's type (`{"abc":x}`), is a
## programming error and panics, like an index out of bounds. Raising instead
## would force `{.raises.}` onto every routine that uses an f-string.

import std / [strutils, repr]
import spec

proc applyWidth(body, prefix: string; fs: FormatSpec; defaultAlign: char): string =
  ## Pads `prefix & body` to `fs.width`. With '=' alignment the padding goes
  ## between the sign/prefix and the digits (as in `+000042`).
  let align = if fs.align == '\0': defaultAlign else: fs.align
  let total = prefix.len + body.len
  if total >= fs.width:
    return prefix & body
  let pad = fs.width - total
  case align
  of '<': result = prefix & body & repeat(fs.fill, pad)
  of '^':
    let left = pad div 2
    result = repeat(fs.fill, left) & prefix & body & repeat(fs.fill, pad - left)
  of '=': result = prefix & repeat(fs.fill, pad) & body
  else: result = repeat(fs.fill, pad) & prefix & body

proc group(digits: string; sep: char; every: int): string =
  result = ""
  let n = digits.len
  for i in 0 ..< n:
    if i > 0 and (n - i) mod every == 0: result.add sep
    result.add digits[i]

proc groupPadded(digits: string; sep: char; every, need: int): string =
  ## Grouping plus zero padding, the way Python does `{x:08,d}`: the padding
  ## zeros are grouped too (`-000,999`, never `-0000999` or `-00999`).
  var d = digits
  result = group(d, sep, every)
  while result.len < need:
    d = "0" & d
    result = group(d, sep, every)

proc zeroPadGroups(fs: FormatSpec): bool {.inline.} =
  fs.grouping != '\0' and fs.fill == '0' and fs.align == '='

proc signPrefix(negative: bool; fs: FormatSpec): string =
  if negative: "-"
  elif fs.sign == '+': "+"
  elif fs.sign == ' ': " "
  else: ""

proc specOrDie(s: string): FormatSpec =
  result = FormatSpec()
  let msg = parseSpec(s, result)
  if msg.len > 0:
    panic(msg)

# ---------------------------------------------------------------- strings

proc fmtString(s: string; fs: FormatSpec): string =
  if fs.typ notin {'\0', 's'}:
    panic("format spec: type '" & charStr(fs.typ) & "' is not valid for strings")
  if fs.sign != '\0' or fs.alternate or fs.grouping != '\0':
    panic("format spec: sign, '#' and grouping are not valid for strings")
  let body = if fs.precision >= 0 and fs.precision < s.len:
               s.substr(0, fs.precision - 1)
             else: s
  result = applyWidth(body, "", fs, '<')

# ---------------------------------------------------------------- floats

proc trimZeros(s: string): string =
  ## "1.2300" -> "1.23", "5.000" -> "5"
  if '.' notin s: return s
  var e = s.len
  while e > 0 and s[e-1] == '0': dec e
  if e > 0 and s[e-1] == '.': dec e
  result = s.substr(0, e - 1)

proc splitExp(s: string; mant: var string; exp: var int) =
  ## "1.2345e+03" -> ("1.2345", 3)
  let k = s.find('e')
  mant = s.substr(0, k - 1)
  exp = 0
  var neg = false
  for i in k + 1 ..< s.len:
    case s[i]
    of '-': neg = true
    of '0'..'9': exp = exp * 10 + (ord(s[i]) - ord('0'))
    else: discard
  if neg: exp = -exp

proc expText(mant: string; exp: int; upper: bool): string =
  ## Python keeps at least two exponent digits: 1e+05, 1e-07, 1e+100.
  let a = abs(exp)
  result = mant & (if upper: "E" else: "e") & (if exp < 0: "-" else: "+") &
           (if a < 10: "0" & $a else: $a)

proc ff(x: float; mode: FloatFormatMode; prec: int): string =
  ## `formatFloat` accepts precisions up to 32; beyond that we clamp.
  ## Nimony's formatFloat leaves a bare '.' at precision 0 ("3.", "3.e+00");
  ## Python does not, so it is removed here ('#' adds it back).
  result = if prec >= 0 and prec <= 32: formatFloat(x, mode, prec)
           else: formatFloat(x, mode, 32)
  if prec == 0:
    let d = result.find('.')
    if d >= 0 and (d == result.len - 1 or result[d+1] in {'e', 'E'}):
      result = result.substr(0, d - 1) & result.substr(d + 1)

proc fmtFloatBody(x: float; typ: char; prec: int; alternate: bool): string =
  ## `x` is finite and non-negative here.
  case typ
  of 'f', 'F', '%':
    let v = if typ == '%': x * 100.0 else: x
    result = ff(v, ffDecimal, prec)
    if prec == 0 and alternate: result.add '.'
    if typ == '%': result.add '%'
  of 'e', 'E':
    var mant = ""
    var exp = 0
    splitExp(ff(x, ffScientific, prec), mant, exp)
    if prec == 0 and alternate: mant.add '.'
    result = expText(mant, exp, typ == 'E')
  else:
    # 'g'/'G', and '\0' = no type but a precision. Python: the latter is
    # like 'g', except fixed notation keeps one digit after the point and
    # scientific notation starts one exponent earlier.
    let p = if prec == 0: 1 else: prec
    let plain = typ == '\0'
    var mant = ""
    var exp = 0
    splitExp(ff(x, ffScientific, p - 1), mant, exp)
    if x == 0.0: exp = 0
    let limit = if plain: p - 1 else: p
    if -4 <= exp and exp < limit:
      result = ff(x, ffDecimal, p - 1 - exp)
      if not alternate: result = trimZeros(result)
      if plain and '.' notin result: result.add ".0"
    else:
      if not alternate: mant = trimZeros(mant)
      result = expText(mant, exp, typ == 'G')

proc fmtFloat(x: float; fs: FormatSpec): string =
  if fs.typ notin {'\0', 'e', 'E', 'f', 'F', 'g', 'G', '%', 'n'}:
    panic("format spec: type '" & charStr(fs.typ) & "' is not valid for floats")
  var negative = x < 0.0 or (x == 0.0 and 1.0 / x < 0.0)
  var v = abs(x)
  var body = ""
  let upper = fs.typ in {'E', 'F', 'G'}
  if x != x:
    body = if upper: "NAN" else: "nan"
    if fs.typ == '%': body.add '%'
    negative = false
  elif v == Inf:
    body = if upper: "INF" else: "inf"
    if fs.typ == '%': body.add '%'
  elif fs.typ == '\0' and fs.precision < 0:
    body = $v      # shortest round-trip text, like Python's repr
    if fs.alternate and '.' notin body and 'e' notin body: body.add '.'
  else:
    let typ = if fs.typ == 'n': 'g' else: fs.typ
    let prec = if fs.precision >= 0: fs.precision else: 6
    body = fmtFloatBody(v, typ, prec, fs.alternate)
  if fs.zeroNeg and negative and body.trimZeros.replace(".", "").replace("0", "").len == 0:
    negative = false
  if fs.grouping != '\0' and body.len > 0 and body[0] in {'0'..'9'}:
    var k = 0
    while k < body.len and body[k] in {'0'..'9'}: inc k
    let rest = body.substr(k)
    let pre = signPrefix(negative, fs)
    let need = if zeroPadGroups(fs): fs.width - pre.len - rest.len else: 0
    body = groupPadded(body.substr(0, k - 1), fs.grouping, 3, need) & rest
    return applyWidth(body, pre, fs, '>')
  result = applyWidth(body, signPrefix(negative, fs), fs, '>')

# ---------------------------------------------------------------- integers

proc toBase(u: uint64; base: uint64; upper: bool): string =
  const lo = "0123456789abcdef"
  const hi = "0123456789ABCDEF"
  if u == 0'u64: return "0"
  result = ""
  var v = u
  while v > 0'u64:
    let d = int(v mod base)
    result.add(if upper: hi[d] else: lo[d])
    v = v div base
  var i = 0
  var j = result.len - 1
  while i < j:
    let tmp = result[i]
    result[i] = result[j]
    result[j] = tmp
    inc i
    dec j

proc fmtInt(negative: bool; mag: uint64; fs: FormatSpec): string =
  case fs.typ
  of 'e', 'E', 'f', 'F', 'g', 'G', '%':
    let f = if negative: -float(mag) else: float(mag)
    return fmtFloat(f, fs)
  of 'c':
    if negative or mag > 255'u64:
      panic("format spec 'c': value out of char range")
    return applyWidth(charStr(char(mag)), "", fs, '<')
  of 's':
    panic("format spec: type 's' is not valid for integers")
  else: discard
  if fs.precision >= 0:
    panic("format spec: precision is not allowed for integers")
  var base = 10'u64
  var prefix = ""
  var every = 3
  case fs.typ
  of 'b':
    base = 2; prefix = "0b"; every = 4
  of 'o':
    base = 8; prefix = "0o"; every = 4
  of 'x':
    base = 16; prefix = "0x"; every = 4
  of 'X':
    base = 16; prefix = "0X"; every = 4
  else: discard
  var digits = toBase(mag, base, fs.typ == 'X')
  if fs.grouping != '\0':
    if fs.grouping == ',' and base != 10'u64:
      panic("format spec: ',' needs a decimal type")
  let pre = signPrefix(negative, fs) & (if fs.alternate: prefix else: "")
  if fs.grouping != '\0':
    let need = if zeroPadGroups(fs): fs.width - pre.len else: 0
    digits = groupPadded(digits, fs.grouping, every, need)
  result = applyWidth(digits, pre, fs, '>')

# ---------------------------------------------------------------- public API

proc fmtField*(x: string; spec: string): string =
  if spec.len == 0: x else: fmtString(x, specOrDie(spec))

proc fmtField*(x: char; spec: string): string =
  if spec.len == 0: charStr(x) else: fmtString(charStr(x), specOrDie(spec))

proc fmtField*(x: bool; spec: string): string =
  ## Like Python: a bool with a numeric type formats as 0/1.
  if spec.len == 0: return $x
  let fs = specOrDie(spec)
  if fs.typ in {'\0', 's'}: fmtString($x, fs)
  else: fmtInt(false, uint64(ord(x)), fs)

proc fmtField*[T: SomeSignedInt](x: T; spec: string): string {.untyped.} =
  if spec.len == 0: return $x
  let v = int64(x)
  # magnitude without overflowing on low(int64)
  let mag = if v < 0'i64: uint64(not v) + 1'u64 else: uint64(v)
  fmtInt(v < 0'i64, mag, specOrDie(spec))

proc fmtField*[T: SomeUnsignedInt](x: T; spec: string): string {.untyped.} =
  if spec.len == 0: return $x
  fmtInt(false, uint64(x), specOrDie(spec))

proc fmtField*[T: SomeFloat](x: T; spec: string): string {.untyped.} =
  if spec.len == 0: return $x
  fmtFloat(float(x), specOrDie(spec))

proc fmtField*[T](x: T; spec: string): string {.untyped.} =
  ## Anything else with a `$` -- objects, seqs, enums, distinct types -- is
  ## stringified first and then formatted as a string.
  fmtField($x, spec)

proc fmtRepr*(x: string): string = repr(x)
proc fmtRepr*(x: char): string = repr(x)
proc fmtRepr*[T](x: T): string {.untyped.} = repr(x)
