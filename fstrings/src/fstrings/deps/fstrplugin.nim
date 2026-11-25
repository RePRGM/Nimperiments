## Nimony template plugin behind `f"..."`: reads the string literal argument,
## compiles it to an ordinary Nim expression and hands that back to the
## compiler, which then type-checks it at the call site.

import plugins, nimparser
import ../core

proc literalOf(arg: NifCursor; ok: var bool): string =
  ## The argument is a string literal, possibly wrapped as `(suf "..." "R")`
  ## for the raw literal of `f"..."`.
  var lit = arg
  if lit.kind == TagLit: lit = firstChild(lit)
  ok = lit.kind == StrLit
  result = if ok: stringValue(lit) else: ""

proc tr(n: NifCursor): NifBuilder =
  let args = callArgs(n)
  var ok = false
  let text = literalOf(args, ok)
  if not ok:
    return errorTree("f-string: the argument must be a string literal", args)
  let compiled = compileFString(text)
  if not compiled.ok:
    return errorTree(compiled.error, args)
  var expr = parseExpr(compiled.code, args.info)
  result = createTree()
  result.takeTree expr

var inp = loadPluginInput()
saveTree tr(inp)
