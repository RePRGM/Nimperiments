## Python-style f-strings for Nimony.
##
## ```nim
## import fstrings
## let name = "Ada"
## let pi = 3.14159
## echo f"Hello {name}! pi = {pi:.2f}, {name=}, {42:#010b}"
## ```
##
## `f"..."` is Nim's generalized raw string literal, so the text arrives
## exactly as written (no backslash escapes, like Python's `rf"..."`).
## `f("...\n")` takes a normal literal when you need escapes.

import fstrings / runtime
export runtime

template f*(s: string): string {.plugin: "fstrings/deps/fstrplugin".}
  ## Compiles `s` into string concatenation at compile time.

template fmt*(s: string): string {.plugin: "fstrings/deps/fstrplugin".}
  ## Same as `f`, under the name Nim 2's `std/strformat` uses.
