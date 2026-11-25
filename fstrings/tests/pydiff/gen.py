import math
ispecs = ["", "d", "+d", " d", "08d", "+08,d", "08,d", "010_b", "09_x", "#011_x", "#x", "#X", "#o", "#b", "_x", ",", "_", ">8", "<8", "^9", "*^11,", "=+10", "x", "b", "e", ".2f", "g", "%", ".1%", "012,.2f", "c"]
fspecs = ["", ".2f", ".0f", "#.0f", "10.3f", "<10.3f", "^12.1f", "+.3f", " .3f", "e", ".3e", "E", ".2E", "#.0e", "g", ".3g", ".10g", "#g", "G", ".4G", "%", ".1%", ",.2f", "_.1f", "012,.2f", "011,.2f", "015.3e", "z.1f", "=+12.2f", "*>12.3g", ".1", ".5", "F"]
sspecs = ["", "s", ">8", "<8", "^9", "*^9", ".2", "8.3", "-<7"]
ints = [0, 1, -1, 7, 42, -42, 65, 255, 999, -999, 1000, 4096, 123456, -1234567, 2**31, -(2**40)+17, 9007199254740993]
floats = [0.0, -0.0, 1.0, -1.0, 0.5, 2.5, 3.14159265, -2.71828, 1e-7, 1.234e-5, 0.0001, 0.1, 123.456, 99999.5, 1e15, 1.5e16, 1e22, -6.02214076e23, 1234567.891, -0.04, 5e-324, 1.7976931348623157e308, float("inf"), float("-inf")]
strs = ["", "a", "Ada", "Lovelace!", "a b c d e f"]
def nimf(x):
    if math.isinf(x): return "Inf" if x > 0 else "-Inf"
    if x == 0 and math.copysign(1,x) < 0: return "-0.0"
    return repr(x)
nim = ["import std/syncio", "import ../../src/fstrings",
       "let ints = @[" + ", ".join(f"{i}'i64" for i in ints) + "]",
       "let floats = @[" + ", ".join(nimf(x) for x in floats) + "]",
       "let strs = @[" + ", ".join('"%s"' % s for s in strs) + "]"]
exp = []
for s in ispecs:
    if s == "c":
        nim.append(f'for v in ints:\n  if v >= 32 and v <= 126: echo f"[{{v:{s}}}]"')
        exp += [f"[{v:{s}}]" for v in ints if 32 <= v <= 126]
    else:
        nim.append(f'for v in ints: echo f"[{{v:{s}}}]"')
        exp += [f"[{v:{s}}]" for v in ints]
for s in fspecs:
    nim.append(f'for v in floats: echo f"[{{v:{s}}}]"')
    exp += [f"[{v:{s}}]" for v in floats]
for s in sspecs:
    nim.append(f'for v in strs: echo f"[{{v:{s}}}]"')
    exp += [f"[{v:{s}}]" for v in strs]
open("diffcheck.nim","w").write("\n".join(nim)+"\n")
open("expected.txt","w").write("\n".join(exp)+"\n")
print(len(exp), "cases")
