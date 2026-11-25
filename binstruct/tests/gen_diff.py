import struct, random, math
random.seed(11)

def lit_str(b):
    return '"' + ''.join('\\x%02x' % x for x in b) + '"'

def rand_case():
    prefix = random.choice(['<', '>', '!', '=', '@', ''])
    codes = 'xcbB?hHiIlLqQefdsp'
    if prefix in ('@', ''):
        codes += 'nNP'
    parts = []
    for _ in range(random.randint(1, 6)):
        c = random.choice(codes)
        if c in 'spx':
            parts.append(f"{random.randint(1 if c == 'p' else 0, 6)}{c}")
        elif random.random() < 0.2:
            parts.append(f"{random.randint(2, 3)}{c}")
        else:
            parts.append(c)
    return prefix + ''.join(parts)

def codes_of(fmt):
    out = []
    i = 1 if fmt and fmt[0] in '@=<>!' else 0
    while i < len(fmt):
        n = ''
        while fmt[i].isdigit(): n += fmt[i]; i += 1
        c = fmt[i]; i += 1
        cnt = int(n) if n else 1
        if c == 'x': continue
        if c in 'sp': out.append((c, cnt))
        else: out += [(c, 1)] * cnt
    return out

nat = struct.calcsize
ranges = {'b':(-128,127),'B':(0,255),'h':(-2**15,2**15-1),'H':(0,2**16-1),
          'i':(-2**31,2**31-1),'I':(0,2**32-1),'q':(-2**63,2**63-1),'Q':(0,2**64-1)}

def rand_value(fmt, c, n):
    native = fmt[:1] in ('@',) or fmt[:1] not in '=<>!'
    if c in 'lL':
        size = struct.calcsize(('@' if native else '<') + c)
        bits = size * 8
        r = (-2**(bits-1), 2**(bits-1)-1) if c == 'l' else (0, 2**bits-1)
    elif c in 'nN':
        r = (-2**63, 2**63-1) if c == 'n' else (0, 2**64-1)
    elif c == 'P': r = (0, 2**64-1)
    elif c in ranges: r = ranges[c]
    if c in ranges or c in 'lLnNP':
        k = random.random()
        if k < 0.3: return random.choice([r[0], r[1], 0, 1])
        return random.randint(r[0], r[1])
    if c == '?': return random.choice([True, False])
    if c == 'c': return bytes([random.randint(0, 255)])
    if c in 'sp': return bytes(random.randint(0,255) for _ in range(random.randint(0, n+2)))
    if c == 'e': return random.choice([0.0, -0.0, 1.5, 65504.0, float('inf'), random.uniform(-60000, 60000), (random.randint(0,2047)+0.5)*2.0**random.randint(-24,5)])
    if c == 'f': return struct.unpack('<f', struct.pack('<f', random.choice([0.1, -2.5, 3.4e38, 1e-40, random.uniform(-1e6, 1e6)])))[0]
    if c == 'd': return random.choice([0.1, -1e300, 5e-324, float('-inf'), random.uniform(-1e9, 1e9)])

def nim_lit(fmt, c, v):
    native = not (fmt[:1] in '=<>!' and fmt[:1] != '')
    if c == '?': return 'true' if v else 'false'
    if c == 'c': return f"char({v[0]})"
    if c in 'sp': return lit_str(v)
    if c == 'e': return f"cast[float64](0x{struct.unpack('<Q', struct.pack('<d', v))[0]:016x}'u64)"
    if c == 'f': return f"cast[float32](0x{struct.unpack('<I', struct.pack('<f', v))[0]:08x}'u32)"
    if c == 'd': return f"cast[float64](0x{struct.unpack('<Q', struct.pack('<d', v))[0]:016x}'u64)"
    t = {'b':'int8','B':'uint8','h':'int16','H':'uint16','i':'int32','I':'uint32',
         'q':'int64','Q':'uint64','n':'int','N':'uint','P':'uint'}.get(c)
    if c == 'l': t = 'clong' if fmt[:1] in ('@', '') or fmt[:1] not in '=<>!' else 'int32'
    if c == 'L': t = 'culong' if fmt[:1] in ('@', '') or fmt[:1] not in '=<>!' else 'uint32'
    if t in ('int64', 'clong', 'int') and v == -2**63:
        return f"{t}(low(int64))"
    if v < 0: return f"{t}({v})"
    if t in ('uint64', 'uint', 'culong'): return f"{t}({v}'u64)"
    return f"{t}({v})"

def show_py(c, v):
    if c == '?': return 'True' if v else 'False'
    if c == 'c': return str(v[0])
    if c in 'efd': return format(struct.unpack('<Q', struct.pack('<d', v))[0], '016x')
    if c in 'sp': return v.hex()
    return str(v)

nim = ['import std/syncio', 'import ../src/binstruct', '',
'''func hx(x: uint64): string =
  const d = "0123456789abcdef"
  result = newString(16)
  for i in 0 ..< 16: result[i] = d[int((x shr uint64(60 - 4*i)) and 15'u64)]
func hxb(a: openArray[byte]): string =
  const d = "0123456789abcdef"
  result = ""
  for b in a:
    result.add d[int(b shr 4)]
    result.add d[int(b and 15)]
func show(x: int8): string = $x
func show(x: uint8): string = $x
func show(x: int16): string = $x
func show(x: uint16): string = $x
func show(x: int32): string = $x
func show(x: uint32): string = $x
func show(x: int64): string = $x
func show(x: uint64): string = $x
func show(x: bool): string = (if x: "True" else: "False")
func show(x: char): string = $ord(x)
func show(x: float32): string = hx(cast[uint64](float64(x)))
func show(x: float64): string = hx(cast[uint64](x))
func show[N: static int](x: array[N, byte]): string = hxb(x)
func show(x: string): string =
  const d = "0123456789abcdef"
  result = ""
  for c in x:
    result.add d[ord(c) shr 4]
    result.add d[ord(c) and 15]
''', 'proc main() {.raises.} =']
expected = []
ncase = 0
while ncase < 220:
    fmt = rand_case()
    items = codes_of(fmt)
    if not items: continue
    vals = [rand_value(fmt, c, n) for c, n in items]
    try:
        data = struct.pack(fmt, *vals)
    except (OverflowError, struct.error):
        continue
    back = struct.unpack(fmt, data)
    ncase += 1
    args = ', '.join(nim_lit(fmt, c, v) for (c, n), v in zip(items, vals))
    nim.append(f'  block:  # {fmt}')
    nim.append(f'    let d = pack("{fmt}", {args})')
    nim.append(f'    echo "{ncase} ", hxb(d), " ", calcsize("{fmt}")')
    nim.append(f'    let t = unpack("{fmt}", d)')
    if len(items) == 1:
        shows = 'show(t)'
    else:
        shows = ', " ", '.join(f'show(t[{k}])' for k in range(len(items)))
    nim.append(f'    echo "{ncase} ", {shows}')
    expected.append(f"{ncase} {data.hex()} {len(data)}")
    expected.append(f"{ncase} " + ' '.join(show_py(c, v) for (c, n), v in zip(items, back)))
nim.append('try: main()\nexcept ErrorCode as e: echo "error ", $e')
open('tdiff.nim', 'w').write('\n'.join(nim) + '\n')
open('tdiff.expected', 'w').write('\n'.join(expected) + '\n')
print(ncase, "cases")
