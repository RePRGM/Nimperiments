## Compile-time half of the f-string implementation.
##
## `compileFString` turns the text of an f-string into the text of an ordinary
## Nim expression, e.g.
##
##   Hello {name}, you are {age:>3} years old{"!" * n}
##
## becomes
##
##   ("Hello " & fmtField((name), "") & ", you are " &
##    fmtField((age), ">3") & " years old" & fmtField(("!" * n), ""))
##
## The plugin hands that text to Nimony's `nimparser.parseExpr`, so this module
## never touches NIF and can be unit-tested with any Nim compiler.

import spec

type
  FResult* = object
    ok*: bool
    code*: string   ## Nim expression text when `ok`
    error*: string  ## human readable message otherwise

proc quoteNim(s: string): string =
  ## `s` as a Nim string literal.
  result = "\""
  for c in s:
    case c
    of '"': result.add "\\\""
    of '\\': result.add "\\\\"
    of '\n': result.add "\\n"
    of '\r': result.add "\\r"
    of '\t': result.add "\\t"
    of '\0'..'\8', '\11', '\12', '\14'..'\31', '\127':
      const hex = "0123456789ABCDEF"
      result.add "\\x"
      result.add hex[ord(c) shr 4]
      result.add hex[ord(c) and 15]
    else: result.add c
  result.add '"'

proc strip(s: string): string =
  var a = 0
  var b = s.len - 1
  while a <= b and s[a] in {' ', '\t', '\n', '\r'}: inc a
  while b >= a and s[b] in {' ', '\t', '\n', '\r'}: dec b
  result = if a > b: "" else: s.substr(a, b)

type
  Scanner = object
    s: string
    i: int
    err: string

proc fail(sc: var Scanner; msg: string) =
  if sc.err.len == 0:
    sc.err = msg & " (at offset " & $sc.i & " of the f-string)"

proc skipNimString(sc: var Scanner) =
  ## `sc.i` is at an opening quote; skip a "...", r"..." or """...""" literal.
  let isRaw = sc.i > 0 and sc.s[sc.i-1] in {'r', 'R'} and
              (sc.i < 2 or sc.s[sc.i-2] notin {'a'..'z', 'A'..'Z', '0'..'9', '_'})
  if sc.i + 2 < sc.s.len and sc.s[sc.i+1] == '"' and sc.s[sc.i+2] == '"':
    sc.i += 3
    while sc.i + 2 < sc.s.len:
      if sc.s[sc.i] == '"' and sc.s[sc.i+1] == '"' and sc.s[sc.i+2] == '"':
        sc.i += 3
        return
      inc sc.i
    sc.fail "unterminated triple-quoted string inside a replacement field"
    sc.i = sc.s.len
    return
  inc sc.i
  while sc.i < sc.s.len:
    let c = sc.s[sc.i]
    if c == '\\' and not isRaw:
      sc.i += 2
    elif c == '"':
      if isRaw and sc.i + 1 < sc.s.len and sc.s[sc.i+1] == '"':
        sc.i += 2       # "" inside a raw string
      else:
        inc sc.i
        return
    else:
      inc sc.i
  sc.fail "unterminated string inside a replacement field"

proc skipCharLit(sc: var Scanner): bool =
  ## 'a', '\n', '\x41' -- but not the ' of a numeric suffix like 1'u8.
  if sc.i > 0 and sc.s[sc.i-1] in {'a'..'z', 'A'..'Z', '0'..'9', '_'}:
    return false
  var j = sc.i + 1
  if j < sc.s.len and sc.s[j] == '\\':
    inc j
    while j < sc.s.len and sc.s[j] != '\'': inc j
  else:
    inc j
  if j < sc.s.len and sc.s[j] == '\'':
    sc.i = j + 1
    result = true
  else:
    result = false

type
  StopAt = enum
    stopFieldEnd   ## '}' only (nested field inside a spec)
    stopTopLevel   ## '}', ':' (spec) or '!' (conversion) at depth 0

proc scanExpr(sc: var Scanner; mode: StopAt): string =
  ## Reads a Nim expression up to the first top-level delimiter, honouring
  ## brackets and string/char literals so `{t["a:b"]}` and `{ {1, 2} }` work.
  let start = sc.i
  var depth = 0
  while sc.i < sc.s.len:
    let c = sc.s[sc.i]
    case c
    of '(', '[', '{':
      inc depth
      inc sc.i
    of ')', ']':
      if depth == 0:
        sc.fail "unbalanced '" & charStr(c) & "' in replacement field"
        return ""
      dec depth
      inc sc.i
    of '}':
      if depth == 0: break
      dec depth
      inc sc.i
    of '"':
      sc.skipNimString()
    of '\'':
      if not sc.skipCharLit(): inc sc.i
    of ':':
      if depth == 0 and mode == stopTopLevel: break
      inc sc.i
    of '!':
      # `!r`/`!s` followed by '}' or ':' is a conversion; `!=` is an operator.
      if depth == 0 and mode == stopTopLevel and sc.i + 1 < sc.s.len and
          sc.s[sc.i+1] in {'r', 's', 'a'}:
        var j = sc.i + 2
        while j < sc.s.len and sc.s[j] == ' ': inc j
        if j < sc.s.len and sc.s[j] in {'}', ':'}: break
      inc sc.i
    else:
      inc sc.i
    if sc.err.len > 0: return ""
  result = sc.s.substr(start, sc.i - 1)

proc splitDebugEquals(expr: string; label: var string): string =
  ## `{x + y = }` -> expression "x + y ", label "x + y = ". Python only treats
  ## a trailing '=' as the debug marker, never `==`, `!=`, `<=` or `>=`.
  var j = expr.len - 1
  while j >= 0 and expr[j] in {' ', '\t'}: dec j
  if j >= 0 and expr[j] == '=' and
      (j == 0 or expr[j-1] notin {'=', '!', '<', '>'}):
    label = expr
    result = expr.substr(0, j - 1)
  else:
    label = ""
    result = expr

proc scanSpec(sc: var Scanner; parts: var seq[string]; isStatic: var bool): string =
  ## The format spec after ':'. Text is literal except for nested `{expr}`
  ## fields, which make the spec dynamic: `{x:{width}.{prec}f}`.
  ## Returns the literal text (meaningful when `isStatic` stays true).
  isStatic = true
  var lit = ""
  result = ""
  while sc.i < sc.s.len and sc.err.len == 0:
    let c = sc.s[sc.i]
    if c == '}':
      break
    elif c == '{':
      inc sc.i
      let inner = strip(sc.scanExpr(stopFieldEnd))
      if sc.err.len > 0: return
      if sc.i >= sc.s.len:
        sc.fail "unterminated nested replacement field in format spec"
        return
      if inner.len == 0:
        sc.fail "empty nested replacement field in format spec"
        return
      inc sc.i                       # the inner '}'
      if lit.len > 0:
        parts.add quoteNim(lit)
        result.add lit
        lit = ""
      parts.add "$(" & inner & ")"
      isStatic = false
    else:
      lit.add c
      inc sc.i
  if lit.len > 0:
    parts.add quoteNim(lit)
    result.add lit

proc compileField(sc: var Scanner; pieces: var seq[string]) =
  ## `sc.i` is just past the opening '{'.
  let raw = sc.scanExpr(stopTopLevel)
  if sc.err.len > 0: return
  if sc.i >= sc.s.len:
    sc.fail "unterminated replacement field: missing '}'"
    return
  var label = ""
  let expr = strip(splitDebugEquals(raw, label))
  if expr.len == 0:
    sc.fail "empty expression in replacement field"
    return

  var conversion = '\0'
  if sc.s[sc.i] == '!':
    conversion = sc.s[sc.i+1]
    sc.i += 2
    while sc.i < sc.s.len and sc.s[sc.i] == ' ': inc sc.i

  var specParts: seq[string] = @[]
  var specIsStatic = true
  var specText = ""
  if sc.i < sc.s.len and sc.s[sc.i] == ':':
    inc sc.i
    specText = sc.scanSpec(specParts, specIsStatic)
    if sc.err.len > 0: return
  if sc.i >= sc.s.len or sc.s[sc.i] != '}':
    sc.fail "expected '}' to close replacement field"
    return
  inc sc.i

  if specIsStatic and specText.len > 0:
    var fs = FormatSpec()
    let msg = parseSpec(specText, fs)
    if msg.len > 0:
      sc.fail msg & " in {" & expr & ":" & specText & "}"
      return

  # Python: `{x=}` with no conversion and no spec shows repr(x).
  if label.len > 0:
    pieces.add quoteNim(label)
    if conversion == '\0' and specParts.len == 0:
      conversion = 'r'

  let specCode =
    if specParts.len == 0: "\"\""
    elif specParts.len == 1: specParts[0]
    else:
      var t = "("
      for k, p in specParts:
        if k > 0: t.add " & "
        t.add p
      t & ")"

  let value =
    case conversion
    of 'r', 'a': "fmtRepr((" & expr & "))"
    of 's': "$(" & expr & ")"
    else: "(" & expr & ")"
  pieces.add "fmtField(" & value & ", " & specCode & ")"

proc compileFString*(s: string): FResult =
  var sc = Scanner(s: s, i: 0, err: "")
  var pieces: seq[string] = @[]
  var lit = ""
  while sc.i < s.len and sc.err.len == 0:
    let c = s[sc.i]
    if c == '{':
      if sc.i + 1 < s.len and s[sc.i+1] == '{':
        lit.add '{'
        sc.i += 2
      else:
        if lit.len > 0:
          pieces.add quoteNim(lit)
          lit = ""
        inc sc.i
        sc.compileField(pieces)
    elif c == '}':
      if sc.i + 1 < s.len and s[sc.i+1] == '}':
        lit.add '}'
        sc.i += 2
      else:
        sc.fail "single '}' is not allowed; write '}}' for a literal brace"
    else:
      lit.add c
      inc sc.i
  if sc.err.len > 0:
    return FResult(ok: false, code: "", error: "f-string: " & sc.err)
  if lit.len > 0:
    pieces.add quoteNim(lit)
  var code = ""
  if pieces.len == 0:
    code = "\"\""
  elif pieces.len == 1 and pieces[0][0] == '"':
    code = pieces[0]
  else:
    code = "("
    for k, p in pieces:
      if k > 0: code.add " & "
      code.add p
    code.add ")"
  result = FResult(ok: true, code: code, error: "")
