import std / [syncio, assertions]
import ../src/fstrings

type Point = object
  x, y: int

proc `$`(p: Point): string = "(" & $p.x & ", " & $p.y & ")"

proc check(got, expected: string) =
  if got != expected:
    echo "FAIL: got ", got, " expected ", expected
    quit 1

let name = "Ada"
let age = 36
let pi = 3.14159265
let big = 1234567
let neg = -42
let w = 10
let p = 3
let pt = Point(x: 1, y: 2)
let xs = @[1, 2, 3]

check f"Hello {name}!", "Hello Ada!"
check f"{name} is {age}", "Ada is 36"
check f"{{literal}} {age}", "{literal} 36"
check f"{age + 1}", "37"
check f"{xs[1] * 10}", "20"
check f"{pt}", "(1, 2)"
check f"{xs}", "@[1, 2, 3]"
check f"{age == 36}", "true"
check f"{age != 36}", "false"
check f"{(if age > 30: ""old"" else: ""young"")}", "old"
check f"{name:>6}|", "   Ada|"
check f"{name:<6}|", "Ada   |"
check f"{name:*^9}", "***Ada***"
check f"{name:.2}", "Ad"
check f"{age:5d}", "   36"
check f"{age:05}", "00036"
check f"{neg:+06d}", "-00042"
check f"{age:+}", "+36"
check f"{big:,}", "1,234,567"
check f"{big:_}", "1_234_567"
check f"{255:x} {255:X} {255:#x} {5:b} {5:#010b} {8:o}", "ff FF 0xff 101 0b00000101 10"
check f"{0xDEADBEEF:_x}", "dead_beef"
check f"{65:c}", "A"
check f"{pi:.2f}", "3.14"
check f"{pi:10.3f}|", "     3.142|"
check f"{pi:<10.3f}|", "3.142     |"
check f"{-pi:.1f}", "-3.1"
check f"{pi:e}", "3.141593e+00"
check f"{12345.678:.2E}", "1.23E+04"
check f"{0.25:%}", "25.000000%"
check f"{0.256:.1%}", "25.6%"
check f"{1234567.891:,.2f}", "1,234,567.89"
check f"{pi:g}", "3.14159"
check f"{0.00001234:g}", "1.234e-05"
check f"{1e20:g}", "1e+20"
check f"{100.0:g}", "100"
check f"{age:.1f}", "36.0"
check f"{pi:{w}.{p}f}|", "     3.142|"
check f"{name:>{w}}", "       Ada"
check f"{name=}", "name=\"Ada\""
check f"{age = }", "age = 36"
check f"{pi=:.2f}", "pi=3.14"
check f"{name!r}", "\"Ada\""
check f"{age!s:>4}", "  36"
check f"{true} {true:d}", "true 1"
check f"{'x'}", "x"
check f"line1\nline2", "line1\\nline2"
check f("tab\t{age}"), "tab\t36"
check f"", ""
check fmt"{age}", "36"
check f"{low(int64)}", "-9223372036854775808"
check f"{low(int64):,}", "-9,223,372,036,854,775,808"
check f"{-999:08,d}", "-000,999"
check f"{255:010_b}", "0_1111_1111"
check f"{1234.5:011,.2f}", "0,001,234.50"
check f"{2.5:.0f} {pi:#.0f} {pi:.0e}", "2 3. 3e+00"
check f"{1.0:.5} {1.0:.1}", "1.0 1e+00"
check f"{Inf:%}", "inf%"
let t = f"{name}"
check t, "Ada"
echo "all f-string tests passed"
