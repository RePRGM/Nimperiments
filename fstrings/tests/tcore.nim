# Unit tests for the compile-time half. Pure Nim: runs under Nimony or Nim 2.
import std / [syncio, assertions]
import ../src/fstrings/core

proc code(s: string): string =
  let r = compileFString(s)
  assert r.ok, r.error
  r.code

proc err(s: string): string =
  let r = compileFString(s)
  assert not r.ok
  r.error

assert code("plain") == "\"plain\""
assert code("") == "\"\""
assert code("{x}") == "(fmtField((x), \"\"))"
assert code("a{x:>8}b") == "(\"a\" & fmtField((x), \">8\") & \"b\")"
assert code("{x!r}") == "(fmtField(fmtRepr((x)), \"\"))"
assert code("{x=}") == "(\"x=\" & fmtField(fmtRepr((x)), \"\"))"
assert code("{x:{w}.{p}f}") ==
  "(fmtField((x), ($(w) & \".\" & $(p) & \"f\")))"
assert code("{t[\"a:b\"]}") == "(fmtField((t[\"a:b\"]), \"\"))"
assert code("{a != b}") == "(fmtField((a != b), \"\"))"
assert code("{ {1, 2} }") == "(fmtField(({1, 2}), \"\"))"
assert code("{{}}") == "\"{}\""
assert err("{").len > 0
assert err("}").len > 0
assert err("{x:Q}").len > 0
echo "core tests passed"
