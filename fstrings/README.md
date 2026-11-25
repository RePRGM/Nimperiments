# fstrings — Python f-strings for Nimony

```nim
import fstrings

let name = "Ada"
let pi = 3.14159265
echo f"Hello {name}! pi ≈ {pi:.2f}, {name=}, {255:#010b}"
# Hello Ada! pi ≈ 3.14, name="Ada", 0b11111111
```

## How it works

Nimony replaces Nim 2 macros with *plugins*: separate programs that the
compiler builds and runs on NIF trees. `f` is a bodiless template backed by
`src/fstrings/deps/fstrplugin.nim`:

1. The plugin reads the string-literal argument (`stringValue`).
2. `core.compileFString` turns it into Nim source text, e.g.
   `f"a{x:>8}b"` → `("a" & fmtField((x), ">8") & "b")`.
   Static format specs are validated here, so `{x:.q}` is a **compile error**
   pointing at the call site.
3. `nimparser.parseExpr` parses that text and the plugin returns the tree;
   the compiler type-checks it in the caller's scope.
4. `runtime.fmtField` overloads apply the spec (ints, floats, strings, bools,
   chars; anything else via `$`).

## Supported syntax

| Python feature | Example |
|---|---|
| expressions | `{a + b}`, `{xs[1]}`, `{p.name}`, `{ {1, 2} }` |
| escapes | `{{` and `}}` |
| full spec mini-language | `[[fill]align][sign][z][#][0][width][,_][.prec][type]` |
| types | `b c d o x X n e E f F g G % s` |
| nested fields in the spec | `{x:{w}.{p}f}` |
| conversions | `{x!r}` (uses `repr`), `{x!s}` |
| self-documenting `=` | `{x=}`, `{x = }`, `{x=:.2f}` |

## Differences from Python

- `f"..."` is a Nim *generalized raw string literal*: backslashes are not
  escapes (like Python `rf"..."`), and a quote inside is written `""`:
  `f"{(if ok: ""yes"" else: ""no"")}"`. Use `f("...\n")` for escapes.
- A top-level `:` starts the spec, so wrap `if`-expressions and object
  constructors in parentheses (Python has the same rule for lambdas).
- A float with no type and no precision (`{x}`, `{x:>10}`) prints like
  Nimony's `$` (`0.0000001`), matching `echo`, not Python's repr (`1e-07`).
- `!r` uses Nim's `repr` (`"Ada"`, not `'Ada'`).
- Nimony has checked exceptions, so an invalid spec that only appears at run
  time (a nested `{w}` field) or a spec that doesn't fit the value's type
  (`{"abc":x}`) panics rather than raising `ValueError`. Static specs are
  checked at compile time.
- Float precision is capped at 32 digits (Nimony's `formatFloat` limit).

## Tests

```sh
cd tests
nimony c -r tfstrings.nim   # end-to-end, 60+ cases
nimony n -r tfstrings.nim   # same, native backend (arkham + nifasm)
nimony c -r tcore.nim       # compile-time half; also runs under Nim 2
pydiff/run.sh n             # 1,349 spec/value pairs diffed against CPython
```

All of these pass on the C and native backends, and the two backends'
outputs are byte-identical. Against CPython, the only differences are the
three plain-float `$` cases described above.

The native backend links no libc, so it needs nothing from C to build an
f-string program. (By contrast, an `importc` of `printf` fails to link on
`nimony n` unless you pass `-d:useLibc`.)

Tested against Nimony and nativenif built from master (Nov 2026).
The plugin API is still young and may change.
