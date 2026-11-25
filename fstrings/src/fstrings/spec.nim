## Python's format-spec mini-language, parsed into a `FormatSpec`.
##
##   [[fill]align][sign][z][#][0][width][grouping][.precision][type]
##
## Pure Nim with no imports, so the very same code runs inside the compile-time
## plugin (to reject bad static specs early) and in the runtime formatter.

type
  FormatSpec* = object
    fill*: char          ## padding character, default ' '
    align*: char         ## '<', '>', '^', '=' or '\0' (type default)
    sign*: char          ## '+', '-', ' ' or '\0'
    zeroNeg*: bool       ## 'z': turn -0.0 into 0.0
    alternate*: bool     ## '#': 0b/0o/0x prefixes, keep trailing zeros in 'g'
    width*: int          ## minimum field width, 0 = none
    grouping*: char      ## ',' or '_' or '\0'
    precision*: int      ## -1 = not given
    typ*: char           ## presentation type or '\0'

proc charStr*(c: char): string =
  ## A one-character string (Nimony's system has no `$` for `char`).
  result = ""
  result.add c

proc isAlign(c: char): bool {.inline.} = c in {'<', '>', '^', '='}

const presentationTypes* = {'b', 'c', 'd', 'o', 'x', 'X', 'n',
                            'e', 'E', 'f', 'F', 'g', 'G', '%', 's'}

proc parseSpec*(s: string; spec: var FormatSpec): string =
  ## Parses `s` into `spec`. Returns "" on success, else an error message.
  spec = FormatSpec(fill: ' ', align: '\0', sign: '\0', zeroNeg: false,
                    alternate: false, width: 0, grouping: '\0',
                    precision: -1, typ: '\0')
  result = ""
  var i = 0
  # [[fill]align]
  if s.len >= 2 and isAlign(s[1]):
    spec.fill = s[0]
    spec.align = s[1]
    i = 2
  elif s.len >= 1 and isAlign(s[0]):
    spec.align = s[0]
    i = 1
  if i < s.len and s[i] in {'+', '-', ' '}:
    spec.sign = s[i]
    inc i
  if i < s.len and s[i] == 'z':
    spec.zeroNeg = true
    inc i
  if i < s.len and s[i] == '#':
    spec.alternate = true
    inc i
  if i < s.len and s[i] == '0':
    # '0' before the width: zero padding that respects the sign.
    if spec.align == '\0':
      spec.fill = '0'
      spec.align = '='
    inc i
  while i < s.len and s[i] in {'0'..'9'}:
    spec.width = spec.width * 10 + (ord(s[i]) - ord('0'))
    if spec.width > 100_000:
      return "format spec: width too large"
    inc i
  if i < s.len and s[i] in {',', '_'}:
    spec.grouping = s[i]
    inc i
  if i < s.len and s[i] == '.':
    inc i
    if i >= s.len or s[i] notin {'0'..'9'}:
      return "format spec: missing precision after '.'"
    spec.precision = 0
    while i < s.len and s[i] in {'0'..'9'}:
      spec.precision = spec.precision * 10 + (ord(s[i]) - ord('0'))
      if spec.precision > 1000:
        return "format spec: precision too large"
      inc i
  if i < s.len:
    if s[i] in presentationTypes:
      spec.typ = s[i]
      inc i
    else:
      return "format spec: unknown presentation type '" & charStr(s[i]) & "'"
  if i < s.len:
    return "format spec: unexpected trailing text \"" & s.substr(i) & "\""
