import std/syncio
import ../src/binstruct

func hx(x: uint64): string =
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

proc main() {.raises.} =
  block:  # =f3H3h2?Q
    let d = pack("=f3H3h2?Q", cast[float32](0x489650a2'u32), uint16(1966), uint16(8279), uint16(65535), int16(-28826), int16(9999), int16(-7167), true, false, uint64(1567766003366382319'u64))
    echo "1 ", hxb(d), " ", calcsize("=f3H3h2?Q")
    let t = unpack("=f3H3h2?Q", d)
    echo "1 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7]), " ", show(t[8]), " ", show(t[9])
  block:  # ebL
    let d = pack("ebL", cast[float64](0x7ff0000000000000'u64), int8(77), culong(0'u64))
    echo "2 ", hxb(d), " ", calcsize("ebL")
    let t = unpack("ebL", d)
    echo "2 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # H
    let d = pack("H", uint16(61602))
    echo "3 ", hxb(d), " ", calcsize("H")
    let t = unpack("H", d)
    echo "3 ", show(t)
  block:  # =QHIle2B
    let d = pack("=QHIle2B", uint64(1'u64), uint16(23288), uint32(809109426), int32(1157588190), cast[float64](0x40effc0000000000'u64), uint8(108), uint8(0))
    echo "4 ", hxb(d), " ", calcsize("=QHIle2B")
    let t = unpack("=QHIle2B", d)
    echo "4 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # <h2B
    let d = pack("<h2B", int16(0), uint8(0), uint8(197))
    echo "5 ", hxb(d), " ", calcsize("<h2B")
    let t = unpack("<h2B", d)
    echo "5 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # <b
    let d = pack("<b", int8(-121))
    echo "6 ", hxb(d), " ", calcsize("<b")
    let t = unpack("<b", d)
    echo "6 ", show(t)
  block:  # @q?d
    let d = pack("@q?d", int64(1), true, cast[float64](0x0000000000000001'u64))
    echo "7 ", hxb(d), " ", calcsize("@q?d")
    let t = unpack("@q?d", d)
    echo "7 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # >ih2pQb
    let d = pack(">ih2pQb", int32(-2147483648), int16(678), "\xc8", uint64(1'u64), int8(127))
    echo "8 ", hxb(d), " ", calcsize(">ih2pQb")
    let t = unpack(">ih2pQb", d)
    echo "8 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # ?
    let d = pack("?", true)
    echo "9 ", hxb(d), " ", calcsize("?")
    let t = unpack("?", d)
    echo "9 ", show(t)
  block:  # !Hb
    let d = pack("!Hb", uint16(7924), int8(0))
    echo "10 ", hxb(d), " ", calcsize("!Hb")
    let t = unpack("!Hb", d)
    echo "10 ", show(t[0]), " ", show(t[1])
  block:  # !2?f4s?3x
    let d = pack("!2?f4s?3x", false, false, cast[float32](0x3dcccccd'u32), "\x26\xf6\x22\x9f", false)
    echo "11 ", hxb(d), " ", calcsize("!2?f4s?3x")
    let t = unpack("!2?f4s?3x", d)
    echo "11 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # >b
    let d = pack(">b", int8(-106))
    echo "12 ", hxb(d), " ", calcsize(">b")
    let t = unpack(">b", d)
    echo "12 ", show(t)
  block:  # ?Lde6xd
    let d = pack("?Lde6xd", false, culong(11231611986178456803'u64), cast[float64](0x3fb999999999999a'u64), cast[float64](0x3ff8000000000000'u64), cast[float64](0xc1aa994e50945518'u64))
    echo "13 ", hxb(d), " ", calcsize("?Lde6xd")
    let t = unpack("?Lde6xd", d)
    echo "13 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # =fb0sl
    let d = pack("=fb0sl", cast[float32](0xc0200000'u32), int8(-71), "\xf8", int32(-2147483648))
    echo "14 ", hxb(d), " ", calcsize("=fb0sl")
    let t = unpack("=fb0sl", d)
    echo "14 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # !?HL
    let d = pack("!?HL", false, uint16(31651), uint32(2860014689))
    echo "15 ", hxb(d), " ", calcsize("!?HL")
    let t = unpack("!?HL", d)
    echo "15 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # >eHQL?c
    let d = pack(">eHQL?c", cast[float64](0x8000000000000000'u64), uint16(1), uint64(18446744073709551615'u64), uint32(2233276979), false, char(231))
    echo "16 ", hxb(d), " ", calcsize(">eHQL?c")
    let t = unpack(">eHQL?c", d)
    echo "16 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # !c
    let d = pack("!c", char(21))
    echo "17 ", hxb(d), " ", calcsize("!c")
    let t = unpack("!c", d)
    echo "17 ", show(t)
  block:  # Il2nQ6xI
    let d = pack("Il2nQ6xI", uint32(0), clong(-987255535944032725), int(8457106399172887523), int(5973753086672898589), uint64(0'u64), uint32(155370491))
    echo "18 ", hxb(d), " ", calcsize("Il2nQ6xI")
    let t = unpack("Il2nQ6xI", d)
    echo "18 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # >q4sh
    let d = pack(">q4sh", int64(-5092725203545414215), "\xc6\x42\xe6", int16(-31887))
    echo "19 ", hxb(d), " ", calcsize(">q4sh")
    let t = unpack(">q4sh", d)
    echo "19 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # =6sL2HHQ
    let d = pack("=6sL2HHQ", "\xa4\x86\x08\xb2", uint32(159493046), uint16(55235), uint16(63890), uint16(28612), uint64(2591771179454788353'u64))
    echo "20 ", hxb(d), " ", calcsize("=6sL2HHQ")
    let t = unpack("=6sL2HHQ", d)
    echo "20 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # >6sfdbf
    let d = pack(">6sfdbf", "\x54\x83\x9f\xc3", cast[float32](0x495e1012'u32), cast[float64](0xfe37e43c8800759c'u64), int8(11), cast[float32](0xc0200000'u32))
    echo "21 ", hxb(d), " ", calcsize(">6sfdbf")
    let t = unpack(">6sfdbf", d)
    echo "21 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # =B2Q3s5pB
    let d = pack("=B2Q3s5pB", uint8(33), uint64(4966117871164259636'u64), uint64(6266004913407455916'u64), "\xa2\x37\x62", "\x0f\x85\x42\x0b\x12\x63", uint8(0))
    echo "22 ", hxb(d), " ", calcsize("=B2Q3s5pB")
    let t = unpack("=B2Q3s5pB", d)
    echo "22 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # LiB
    let d = pack("LiB", culong(13239158651440351384'u64), int32(1626639663), uint8(1))
    echo "23 ", hxb(d), " ", calcsize("LiB")
    let t = unpack("LiB", d)
    echo "23 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # @hPH5pn
    let d = pack("@hPH5pn", int16(0), uint(11125738647043513072'u64), uint16(25517), "\x63\x31\x44", int(4179598955965726259))
    echo "24 ", hxb(d), " ", calcsize("@hPH5pn")
    let t = unpack("@hPH5pn", d)
    echo "24 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # !Be?0x
    let d = pack("!Be?0x", uint8(0), cast[float64](0x40e81a98378e5388'u64), false)
    echo "25 ", hxb(d), " ", calcsize("!Be?0x")
    let t = unpack("!Be?0x", d)
    echo "25 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # @H2d5p4s2dB
    let d = pack("@H2d5p4s2dB", uint16(37105), cast[float64](0x3fb999999999999a'u64), cast[float64](0xfe37e43c8800759c'u64), "\x27\x31\xa7\xc8\xef\xda\xb5", "\x6b\xbf\x06", cast[float64](0x3fb999999999999a'u64), cast[float64](0xfe37e43c8800759c'u64), uint8(184))
    echo "26 ", hxb(d), " ", calcsize("@H2d5p4s2dB")
    let t = unpack("@H2d5p4s2dB", d)
    echo "26 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7])
  block:  # Q2NL
    let d = pack("Q2NL", uint64(4764134451354291624'u64), uint(14115986095531373682'u64), uint(3409279862244806822'u64), culong(8648578781129966690'u64))
    echo "27 ", hxb(d), " ", calcsize("Q2NL")
    let t = unpack("Q2NL", d)
    echo "27 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # <clQ
    let d = pack("<clQ", char(39), int32(2146998397), uint64(13628360134696216245'u64))
    echo "28 ", hxb(d), " ", calcsize("<clQ")
    let t = unpack("<clQ", d)
    echo "28 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # !QH0xI
    let d = pack("!QH0xI", uint64(11769255176622439605'u64), uint16(9987), uint32(4103171105))
    echo "29 ", hxb(d), " ", calcsize("!QH0xI")
    let t = unpack("!QH0xI", d)
    echo "29 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # =Qh
    let d = pack("=Qh", uint64(1079970607178206643'u64), int16(22374))
    echo "30 ", hxb(d), " ", calcsize("=Qh")
    let t = unpack("=Qh", d)
    echo "30 ", show(t[0]), " ", show(t[1])
  block:  # !Qqd3p2l
    let d = pack("!Qqd3p2l", uint64(2888528215524756892'u64), int64(4581490823437043614), cast[float64](0x0000000000000001'u64), "", int32(-1186678081), int32(1097360637))
    echo "31 ", hxb(d), " ", calcsize("!Qqd3p2l")
    let t = unpack("!Qqd3p2l", d)
    echo "31 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # <B2f3B2fq
    let d = pack("<B2f3B2fq", uint8(1), cast[float32](0x000116c2'u32), cast[float32](0x7f7fc99e'u32), uint8(214), uint8(70), uint8(65), cast[float32](0x3dcccccd'u32), cast[float32](0x7f7fc99e'u32), int64(6392934045390369916))
    echo "32 ", hxb(d), " ", calcsize("<B2f3B2fq")
    let t = unpack("<B2f3B2fq", d)
    echo "32 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7]), " ", show(t[8])
  block:  # !H2i5s
    let d = pack("!H2i5s", uint16(5178), int32(-2106785464), int32(-2147483648), "")
    echo "33 ", hxb(d), " ", calcsize("!H2i5s")
    let t = unpack("!H2i5s", d)
    echo "33 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # <3pb
    let d = pack("<3pb", "\x52\x78\xbf\xf7\xf5", int8(45))
    echo "34 ", hxb(d), " ", calcsize("<3pb")
    let t = unpack("<3pb", d)
    echo "34 ", show(t[0]), " ", show(t[1])
  block:  # !?bfH
    let d = pack("!?bfH", false, int8(-51), cast[float32](0xc87ff501'u32), uint16(24099))
    echo "35 ", hxb(d), " ", calcsize("!?bfH")
    let t = unpack("!?bfH", d)
    echo "35 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # =qfbedf
    let d = pack("=qfbedf", int64(-3502191821176836400), cast[float32](0x4948877f'u32), int8(0), cast[float64](0x8000000000000000'u64), cast[float64](0x0000000000000001'u64), cast[float32](0x3dcccccd'u32))
    echo "36 ", hxb(d), " ", calcsize("=qfbedf")
    let t = unpack("=qfbedf", d)
    echo "36 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # !fIli1sb
    let d = pack("!fIli1sb", cast[float32](0x7f7fc99e'u32), uint32(2511734132), int32(-1386036048), int32(1), "\x0b\x71", int8(-47))
    echo "37 ", hxb(d), " ", calcsize("!fIli1sb")
    let t = unpack("!fIli1sb", d)
    echo "37 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # @5x3e1p
    let d = pack("@5x3e1p", cast[float64](0x0000000000000000'u64), cast[float64](0x40e76213f0ee6372'u64), cast[float64](0x4068f80000000000'u64), "\x7d\x70\xfa")
    echo "38 ", hxb(d), " ", calcsize("@5x3e1p")
    let t = unpack("@5x3e1p", d)
    echo "38 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # @fLL
    let d = pack("@fLL", cast[float32](0xc6461055'u32), culong(852990056627694644'u64), culong(12299116280599193018'u64))
    echo "39 ", hxb(d), " ", calcsize("@fLL")
    let t = unpack("@fLL", d)
    echo "39 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # <b6p4xq
    let d = pack("<b6p4xq", int8(87), "\x4a\x7d\x53\xc0\x55\xa4", int64(1))
    echo "40 ", hxb(d), " ", calcsize("<b6p4xq")
    let t = unpack("<b6p4xq", d)
    echo "40 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # @IcB
    let d = pack("@IcB", uint32(4294967295), char(31), uint8(8))
    echo "41 ", hxb(d), " ", calcsize("@IcB")
    let t = unpack("@IcB", d)
    echo "41 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # @c2Hnd
    let d = pack("@c2Hnd", char(114), uint16(36839), uint16(40859), int(6518899349588536892), cast[float64](0xfff0000000000000'u64))
    echo "42 ", hxb(d), " ", calcsize("@c2Hnd")
    let t = unpack("@c2Hnd", d)
    echo "42 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # !1pd2QQ6sI
    let d = pack("!1pd2QQ6sI", "", cast[float64](0xfe37e43c8800759c'u64), uint64(13157831813585837197'u64), uint64(7669653466285092578'u64), uint64(11427706917086890404'u64), "\x1b\x4d\x5b\x00\x68\x4c\x41\x2a", uint32(2267519093))
    echo "43 ", hxb(d), " ", calcsize("!1pd2QQ6sI")
    let t = unpack("!1pd2QQ6sI", d)
    echo "43 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # =3f6xHbf4p
    let d = pack("=3f6xHbf4p", cast[float32](0xc0200000'u32), cast[float32](0x7f7fc99e'u32), cast[float32](0x000116c2'u32), uint16(0), int8(-94), cast[float32](0xc0200000'u32), "")
    echo "44 ", hxb(d), " ", calcsize("=3f6xHbf4p")
    let t = unpack("=3f6xHbf4p", d)
    echo "44 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # fB6xQ
    let d = pack("fB6xQ", cast[float32](0x7f7fc99e'u32), uint8(234), uint64(13267440712794292676'u64))
    echo "45 ", hxb(d), " ", calcsize("fB6xQ")
    let t = unpack("fB6xQ", d)
    echo "45 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # @l6p
    let d = pack("@l6p", clong(0), "\x2c\x83\x60\x66\xc0\x38")
    echo "46 ", hxb(d), " ", calcsize("@l6p")
    let t = unpack("@l6p", d)
    echo "46 ", show(t[0]), " ", show(t[1])
  block:  # !IL2Q
    let d = pack("!IL2Q", uint32(769849339), uint32(0), uint64(12985339065107597162'u64), uint64(0'u64))
    echo "47 ", hxb(d), " ", calcsize("!IL2Q")
    let t = unpack("!IL2Q", d)
    echo "47 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # >e
    let d = pack(">e", cast[float64](0x7ff0000000000000'u64))
    echo "48 ", hxb(d), " ", calcsize(">e")
    let t = unpack(">e", d)
    echo "48 ", show(t)
  block:  # >HQeQLi
    let d = pack(">HQeQLi", uint16(2430), uint64(18446744073709551615'u64), cast[float64](0x7ff0000000000000'u64), uint64(15222043231398220661'u64), uint32(680073719), int32(1730857929))
    echo "49 ", hxb(d), " ", calcsize(">HQeQLi")
    let t = unpack(">HQeQLi", d)
    echo "49 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # @q1s
    let d = pack("@q1s", int64(5102633783738860832), "\x7d")
    echo "50 ", hxb(d), " ", calcsize("@q1s")
    let t = unpack("@q1s", d)
    echo "50 ", show(t[0]), " ", show(t[1])
  block:  # =e3LIB?
    let d = pack("=e3LIB?", cast[float64](0x3ff8000000000000'u64), uint32(0), uint32(3541853109), uint32(0), uint32(0), uint8(95), true)
    echo "51 ", hxb(d), " ", calcsize("=e3LIB?")
    let t = unpack("=e3LIB?", d)
    echo "51 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # =2Q
    let d = pack("=2Q", uint64(301588865887065182'u64), uint64(1'u64))
    echo "52 ", hxb(d), " ", calcsize("=2Q")
    let t = unpack("=2Q", d)
    echo "52 ", show(t[0]), " ", show(t[1])
  block:  # <3sB
    let d = pack("<3sB", "\xac", uint8(134))
    echo "53 ", hxb(d), " ", calcsize("<3sB")
    let t = unpack("<3sB", d)
    echo "53 ", show(t[0]), " ", show(t[1])
  block:  # >2L?dde
    let d = pack(">2L?dde", uint32(4271838287), uint32(1863829128), true, cast[float64](0x41c82797db828e20'u64), cast[float64](0xc1b438de47905590'u64), cast[float64](0x0000000000000000'u64))
    echo "54 ", hxb(d), " ", calcsize(">2L?dde")
    let t = unpack(">2L?dde", d)
    echo "54 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # !eLlbfQ
    let d = pack("!eLlbfQ", cast[float64](0x8000000000000000'u64), uint32(2821123702), int32(1631024967), int8(60), cast[float32](0x000116c2'u32), uint64(16665055759975309319'u64))
    echo "55 ", hxb(d), " ", calcsize("!eLlbfQ")
    let t = unpack("!eLlbfQ", d)
    echo "55 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # <3?2xi2x3h
    let d = pack("<3?2xi2x3h", false, true, false, int32(-1156229293), int16(26853), int16(7582), int16(-13995))
    echo "56 ", hxb(d), " ", calcsize("<3?2xi2x3h")
    let t = unpack("<3?2xi2x3h", d)
    echo "56 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # =H3c
    let d = pack("=H3c", uint16(2101), char(88), char(103), char(120))
    echo "57 ", hxb(d), " ", calcsize("=H3c")
    let t = unpack("=H3c", d)
    echo "57 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # >B
    let d = pack(">B", uint8(140))
    echo "58 ", hxb(d), " ", calcsize(">B")
    let t = unpack(">B", d)
    echo "58 ", show(t)
  block:  # =?fh2l2I5s
    let d = pack("=?fh2l2I5s", false, cast[float32](0x7f7fc99e'u32), int16(-17596), int32(1832872693), int32(-958487117), uint32(386476460), uint32(2269022599), "")
    echo "59 ", hxb(d), " ", calcsize("=?fh2l2I5s")
    let t = unpack("=?fh2l2I5s", d)
    echo "59 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7])
  block:  # <le2b2ih
    let d = pack("<le2b2ih", int32(-2147483648), cast[float64](0x40effc0000000000'u64), int8(-128), int8(56), int32(136067813), int32(1164939566), int16(1))
    echo "60 ", hxb(d), " ", calcsize("<le2b2ih")
    let t = unpack("<le2b2ih", d)
    echo "60 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # >fIi2pdH
    let d = pack(">fIi2pdH", cast[float32](0x48d1afe4'u32), uint32(3782355135), int32(465148408), "\xfe\xde\xe2\x86", cast[float64](0x3fb999999999999a'u64), uint16(65535))
    echo "61 ", hxb(d), " ", calcsize(">fIi2pdH")
    let t = unpack(">fIi2pdH", d)
    echo "61 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # @5piccNI
    let d = pack("@5piccNI", "\x2d\x57\xc1\x82\x7f\x51\xfe", int32(1231387758), char(31), char(161), uint(12887865429884317241'u64), uint32(4111177698))
    echo "62 ", hxb(d), " ", calcsize("@5piccNI")
    let t = unpack("@5piccNI", d)
    echo "62 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # >3?5s3c1s
    let d = pack(">3?5s3c1s", true, false, false, "\xd9\x27\x11\x75\x97\x81\x3c", char(123), char(214), char(236), "")
    echo "63 ", hxb(d), " ", calcsize(">3?5s3c1s")
    let t = unpack(">3?5s3c1s", d)
    echo "63 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7])
  block:  # >l3Hc
    let d = pack(">l3Hc", int32(-1386074099), uint16(27960), uint16(6455), uint16(0), char(126))
    echo "64 ", hxb(d), " ", calcsize(">l3Hc")
    let t = unpack(">l3Hc", d)
    echo "64 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # >hQfdh
    let d = pack(">hQfdh", int16(1), uint64(12753250944327801077'u64), cast[float32](0x7f7fc99e'u32), cast[float64](0x41acd75fd8eea8c8'u64), int16(0))
    echo "65 ", hxb(d), " ", calcsize(">hQfdh")
    let t = unpack(">hQfdh", d)
    echo "65 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # @nH3q?
    let d = pack("@nH3q?", int(-7023706057025926003), uint16(50385), int64(7053786568129231717), int64(-8210523938475603585), int64(-213496848961159547), true)
    echo "66 ", hxb(d), " ", calcsize("@nH3q?")
    let t = unpack("@nH3q?", d)
    echo "66 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # >3?e6p?3p
    let d = pack(">3?e6p?3p", false, false, false, cast[float64](0x3ff8000000000000'u64), "\xe6\xcf\x45\xc5\xb6\x73\x34\x95", false, "\x6e\x47")
    echo "67 ", hxb(d), " ", calcsize(">3?e6p?3p")
    let t = unpack(">3?e6p?3p", d)
    echo "67 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # <d
    let d = pack("<d", cast[float64](0x0000000000000001'u64))
    echo "68 ", hxb(d), " ", calcsize("<d")
    let t = unpack("<d", d)
    echo "68 ", show(t)
  block:  # bHqqP3e
    let d = pack("bHqqP3e", int8(1), uint16(37298), int64(-5135085549553328828), int64(4478420141479163745), uint(2781643183390435546'u64), cast[float64](0x0000000000000000'u64), cast[float64](0x0000000000000000'u64), cast[float64](0x40effc0000000000'u64))
    echo "69 ", hxb(d), " ", calcsize("bHqqP3e")
    let t = unpack("bHqqP3e", d)
    echo "69 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7])
  block:  # =lL3bLl
    let d = pack("=lL3bLl", int32(-132085811), uint32(1557465446), int8(-18), int8(-104), int8(82), uint32(273280297), int32(1))
    echo "70 ", hxb(d), " ", calcsize("=lL3bLl")
    let t = unpack("=lL3bLl", d)
    echo "70 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # =2Q2sld
    let d = pack("=2Q2sld", uint64(18446744073709551615'u64), uint64(0'u64), "\x78", int32(2060690953), cast[float64](0xc1cd980844259582'u64))
    echo "71 ", hxb(d), " ", calcsize("=2Q2sld")
    let t = unpack("=2Q2sld", d)
    echo "71 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # =1p6pLBLH
    let d = pack("=1p6pLBLH", "\x62", "\x51\xaa", uint32(2421569251), uint8(146), uint32(2140473701), uint16(47477))
    echo "72 ", hxb(d), " ", calcsize("=1p6pLBLH")
    let t = unpack("=1p6pLBLH", d)
    echo "72 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # !h?b3l6s3d
    let d = pack("!h?b3l6s3d", int16(-25764), false, int8(1), int32(0), int32(785287360), int32(2147483647), "\xd7\x40", cast[float64](0x0000000000000001'u64), cast[float64](0xfe37e43c8800759c'u64), cast[float64](0xc1c1d48861f09eba'u64))
    echo "73 ", hxb(d), " ", calcsize("!h?b3l6s3d")
    let t = unpack("!h?b3l6s3d", d)
    echo "73 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7]), " ", show(t[8]), " ", show(t[9])
  block:  # i3xn
    let d = pack("i3xn", int32(1836175633), int(0))
    echo "74 ", hxb(d), " ", calcsize("i3xn")
    let t = unpack("i3xn", d)
    echo "74 ", show(t[0]), " ", show(t[1])
  block:  # =Q2?3c
    let d = pack("=Q2?3c", uint64(14787700755198262338'u64), false, false, char(13), char(247), char(87))
    echo "75 ", hxb(d), " ", calcsize("=Q2?3c")
    let t = unpack("=Q2?3c", d)
    echo "75 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # !l
    let d = pack("!l", int32(642508411))
    echo "76 ", hxb(d), " ", calcsize("!l")
    let t = unpack("!l", d)
    echo "76 ", show(t)
  block:  # >eQH?
    let d = pack(">eQH?", cast[float64](0x40effc0000000000'u64), uint64(2649657991264940947'u64), uint16(35915), false)
    echo "77 ", hxb(d), " ", calcsize(">eQH?")
    let t = unpack(">eQH?", d)
    echo "77 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # >d
    let d = pack(">d", cast[float64](0x41988bd4814b62b0'u64))
    echo "78 ", hxb(d), " ", calcsize(">d")
    let t = unpack(">d", d)
    echo "78 ", show(t)
  block:  # <3b3b
    let d = pack("<3b3b", int8(-25), int8(81), int8(84), int8(74), int8(-18), int8(1))
    echo "79 ", hxb(d), " ", calcsize("<3b3b")
    let t = unpack("<3b3b", d)
    echo "79 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # !lf
    let d = pack("!lf", int32(-1945661961), cast[float32](0xc0200000'u32))
    echo "80 ", hxb(d), " ", calcsize("!lf")
    let t = unpack("!lf", d)
    echo "80 ", show(t[0]), " ", show(t[1])
  block:  # @b
    let d = pack("@b", int8(0))
    echo "81 ", hxb(d), " ", calcsize("@b")
    let t = unpack("@b", d)
    echo "81 ", show(t)
  block:  # <2fb6x2si
    let d = pack("<2fb6x2si", cast[float32](0x000116c2'u32), cast[float32](0xc8bb8ced'u32), int8(-77), "\xcd\xd1\x80", int32(531337850))
    echo "82 ", hxb(d), " ", calcsize("<2fb6x2si")
    let t = unpack("<2fb6x2si", d)
    echo "82 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # <?Q5sIq
    let d = pack("<?Q5sIq", false, uint64(4881525452396183948'u64), "\x5c\x6c\x18", uint32(2346076334), int64(-2813560816318338889))
    echo "83 ", hxb(d), " ", calcsize("<?Q5sIq")
    let t = unpack("<?Q5sIq", d)
    echo "83 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # >q3e
    let d = pack(">q3e", int64(-7475763942757621354), cast[float64](0x8000000000000000'u64), cast[float64](0x3ff8000000000000'u64), cast[float64](0x40effc0000000000'u64))
    echo "84 ", hxb(d), " ", calcsize(">q3e")
    let t = unpack(">q3e", d)
    echo "84 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # 3IL
    let d = pack("3IL", uint32(43288333), uint32(2845399762), uint32(237519369), culong(16373904476302931114'u64))
    echo "85 ", hxb(d), " ", calcsize("3IL")
    let t = unpack("3IL", d)
    echo "85 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # enBffQ
    let d = pack("enBffQ", cast[float64](0x0000000000000000'u64), int(-981091865587568044), uint8(27), cast[float32](0xc0200000'u32), cast[float32](0x7f7fc99e'u32), uint64(11489743071427237425'u64))
    echo "86 ", hxb(d), " ", calcsize("enBffQ")
    let t = unpack("enBffQ", d)
    echo "86 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # >d2Q2d?B2I
    let d = pack(">d2Q2d?B2I", cast[float64](0x0000000000000001'u64), uint64(8376033247788345500'u64), uint64(7873795674382574700'u64), cast[float64](0xfe37e43c8800759c'u64), cast[float64](0xc1c96b205a0b7150'u64), false, uint8(251), uint32(4044393084), uint32(766798179))
    echo "87 ", hxb(d), " ", calcsize(">d2Q2d?B2I")
    let t = unpack(">d2Q2d?B2I", d)
    echo "87 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7]), " ", show(t[8])
  block:  # !q
    let d = pack("!q", int64(0))
    echo "88 ", hxb(d), " ", calcsize("!q")
    let t = unpack("!q", d)
    echo "88 ", show(t)
  block:  # <h6xf2b
    let d = pack("<h6xf2b", int16(8703), cast[float32](0xc0200000'u32), int8(92), int8(45))
    echo "89 ", hxb(d), " ", calcsize("<h6xf2b")
    let t = unpack("<h6xf2b", d)
    echo "89 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # PN2H
    let d = pack("PN2H", uint(1'u64), uint(0'u64), uint16(0), uint16(46863))
    echo "90 ", hxb(d), " ", calcsize("PN2H")
    let t = unpack("PN2H", d)
    echo "90 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # !0xH
    let d = pack("!0xH", uint16(40667))
    echo "91 ", hxb(d), " ", calcsize("!0xH")
    let t = unpack("!0xH", d)
    echo "91 ", show(t)
  block:  # =3?e
    let d = pack("=3?e", false, false, false, cast[float64](0x3ff8000000000000'u64))
    echo "92 ", hxb(d), " ", calcsize("=3?e")
    let t = unpack("=3?e", d)
    echo "92 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # @e2nlbfd
    let d = pack("@e2nlbfd", cast[float64](0x40dc82b88ae8a34c'u64), int(1), int(-4286170902525457340), clong(-8944315662551620815), int8(0), cast[float32](0x7f7fc99e'u32), cast[float64](0xc1b2e2ec35daccf8'u64))
    echo "93 ", hxb(d), " ", calcsize("@e2nlbfd")
    let t = unpack("@e2nlbfd", d)
    echo "93 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # <B3H2x5xq
    let d = pack("<B3H2x5xq", uint8(11), uint16(20408), uint16(47414), uint16(0), int64(1946902450374198779))
    echo "94 ", hxb(d), " ", calcsize("<B3H2x5xq")
    let t = unpack("<B3H2x5xq", d)
    echo "94 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # >Q
    let d = pack(">Q", uint64(0'u64))
    echo "95 ", hxb(d), " ", calcsize(">Q")
    let t = unpack(">Q", d)
    echo "95 ", show(t)
  block:  # <f
    let d = pack("<f", cast[float32](0xc0200000'u32))
    echo "96 ", hxb(d), " ", calcsize("<f")
    let t = unpack("<f", d)
    echo "96 ", show(t)
  block:  # @H?B3bd
    let d = pack("@H?B3bd", uint16(1), true, uint8(0), int8(-116), int8(1), int8(-72), cast[float64](0x3fb999999999999a'u64))
    echo "97 ", hxb(d), " ", calcsize("@H?B3bd")
    let t = unpack("@H?B3bd", d)
    echo "97 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # !2B?4sli
    let d = pack("!2B?4sli", uint8(27), uint8(231), true, "\x35\xeb\x46\x35", int32(16155962), int32(2147483647))
    echo "98 ", hxb(d), " ", calcsize("!2B?4sli")
    let t = unpack("!2B?4sli", d)
    echo "98 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # =B1x?B2Q
    let d = pack("=B1x?B2Q", uint8(252), false, uint8(23), uint64(1445331009777890286'u64), uint64(0'u64))
    echo "99 ", hxb(d), " ", calcsize("=B1x?B2Q")
    let t = unpack("=B1x?B2Q", d)
    echo "99 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # LH2pn
    let d = pack("LH2pn", culong(4764452316890421913'u64), uint16(56263), "\xc4\xb7\xdc", int(-8308999857249022788))
    echo "100 ", hxb(d), " ", calcsize("LH2pn")
    let t = unpack("LH2pn", d)
    echo "100 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # @h
    let d = pack("@h", int16(19626))
    echo "101 ", hxb(d), " ", calcsize("@h")
    let t = unpack("@h", d)
    echo "101 ", show(t)
  block:  # >Bcd5s3s2x
    let d = pack(">Bcd5s3s2x", uint8(53), char(3), cast[float64](0x0000000000000001'u64), "\xbb\xbc\x9a", "\x1c")
    echo "102 ", hxb(d), " ", calcsize(">Bcd5s3s2x")
    let t = unpack(">Bcd5s3s2x", d)
    echo "102 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # !3dc
    let d = pack("!3dc", cast[float64](0xc1c116a344c7c3e1'u64), cast[float64](0xfff0000000000000'u64), cast[float64](0x0000000000000001'u64), char(205))
    echo "103 ", hxb(d), " ", calcsize("!3dc")
    let t = unpack("!3dc", d)
    echo "103 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # <2BI2L
    let d = pack("<2BI2L", uint8(144), uint8(1), uint32(0), uint32(3982793226), uint32(3232963928))
    echo "104 ", hxb(d), " ", calcsize("<2BI2L")
    let t = unpack("<2BI2L", d)
    echo "104 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # @6xdP2bf
    let d = pack("@6xdP2bf", cast[float64](0xfff0000000000000'u64), uint(2176319683909196702'u64), int8(-92), int8(54), cast[float32](0x48a2599b'u32))
    echo "105 ", hxb(d), " ", calcsize("@6xdP2bf")
    let t = unpack("@6xdP2bf", d)
    echo "105 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # B
    let d = pack("B", uint8(58))
    echo "106 ", hxb(d), " ", calcsize("B")
    let t = unpack("B", d)
    echo "106 ", show(t)
  block:  # >e
    let d = pack(">e", cast[float64](0x3f3f980000000000'u64))
    echo "107 ", hxb(d), " ", calcsize(">e")
    let t = unpack(">e", d)
    echo "107 ", show(t)
  block:  # !3eQdQ
    let d = pack("!3eQdQ", cast[float64](0x7ff0000000000000'u64), cast[float64](0x3f7e400000000000'u64), cast[float64](0x7ff0000000000000'u64), uint64(7167591462594002726'u64), cast[float64](0xfff0000000000000'u64), uint64(2727056703617329938'u64))
    echo "108 ", hxb(d), " ", calcsize("!3eQdQ")
    let t = unpack("!3eQdQ", d)
    echo "108 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # 3Liq2n
    let d = pack("3Liq2n", culong(6964968231009967614'u64), culong(10321507269626544598'u64), culong(9795491251143683942'u64), int32(-1642642813), int64(low(int64)), int(6409002204705368178), int(0))
    echo "109 ", hxb(d), " ", calcsize("3Liq2n")
    let t = unpack("3Liq2n", d)
    echo "109 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # @4pL
    let d = pack("@4pL", "\xb6\x9a\x32", culong(18446744073709551615'u64))
    echo "110 ", hxb(d), " ", calcsize("@4pL")
    let t = unpack("@4pL", d)
    echo "110 ", show(t[0]), " ", show(t[1])
  block:  # >6p2q
    let d = pack(">6p2q", "\xbc\xa6", int64(-4340141053427116838), int64(low(int64)))
    echo "111 ", hxb(d), " ", calcsize(">6p2q")
    let t = unpack(">6p2q", d)
    echo "111 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # >Il?bl
    let d = pack(">Il?bl", uint32(1673591367), int32(594657213), false, int8(0), int32(182697924))
    echo "112 ", hxb(d), " ", calcsize(">Il?bl")
    let t = unpack(">Il?bl", d)
    echo "112 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # =qH2sq
    let d = pack("=qH2sq", int64(low(int64)), uint16(9409), "\x01\x34", int64(-7014896902776058244))
    echo "113 ", hxb(d), " ", calcsize("=qH2sq")
    let t = unpack("=qH2sq", d)
    echo "113 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # !qc3b
    let d = pack("!qc3b", int64(-7799415265789826739), char(94), int8(0), int8(-27), int8(-76))
    echo "114 ", hxb(d), " ", calcsize("!qc3b")
    let t = unpack("!qc3b", d)
    echo "114 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # =3d4x
    let d = pack("=3d4x", cast[float64](0x41ca38f528c4362e'u64), cast[float64](0x0000000000000001'u64), cast[float64](0xfe37e43c8800759c'u64))
    echo "115 ", hxb(d), " ", calcsize("=3d4x")
    let t = unpack("=3d4x", d)
    echo "115 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # ??4x
    let d = pack("??4x", false, false)
    echo "116 ", hxb(d), " ", calcsize("??4x")
    let t = unpack("??4x", d)
    echo "116 ", show(t[0]), " ", show(t[1])
  block:  # >1s
    let d = pack(">1s", "")
    echo "117 ", hxb(d), " ", calcsize(">1s")
    let t = unpack(">1s", d)
    echo "117 ", show(t)
  block:  # <l
    let d = pack("<l", int32(-2044134013))
    echo "118 ", hxb(d), " ", calcsize("<l")
    let t = unpack("<l", d)
    echo "118 ", show(t)
  block:  # <h6s
    let d = pack("<h6s", int16(-21882), "")
    echo "119 ", hxb(d), " ", calcsize("<h6s")
    let t = unpack("<h6s", d)
    echo "119 ", show(t[0]), " ", show(t[1])
  block:  # !H
    let d = pack("!H", uint16(53428))
    echo "120 ", hxb(d), " ", calcsize("!H")
    let t = unpack("!H", d)
    echo "120 ", show(t)
  block:  # !i6xi
    let d = pack("!i6xi", int32(751194067), int32(1640108174))
    echo "121 ", hxb(d), " ", calcsize("!i6xi")
    let t = unpack("!i6xi", d)
    echo "121 ", show(t[0]), " ", show(t[1])
  block:  # >?f
    let d = pack(">?f", false, cast[float32](0xc919e505'u32))
    echo "122 ", hxb(d), " ", calcsize(">?f")
    let t = unpack(">?f", d)
    echo "122 ", show(t[0]), " ", show(t[1])
  block:  # !4sI1xll
    let d = pack("!4sI1xll", "\x68\x11\x7e\x2f\x28", uint32(2163114583), int32(-1954551703), int32(-1554530645))
    echo "123 ", hxb(d), " ", calcsize("!4sI1xll")
    let t = unpack("!4sI1xll", d)
    echo "123 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # bQe
    let d = pack("bQe", int8(45), uint64(13678336811534274297'u64), cast[float64](0x40effc0000000000'u64))
    echo "124 ", hxb(d), " ", calcsize("bQe")
    let t = unpack("bQe", d)
    echo "124 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # <b2hhi
    let d = pack("<b2hhi", int8(-59), int16(0), int16(-7516), int16(32767), int32(-198641971))
    echo "125 ", hxb(d), " ", calcsize("<b2hhi")
    let t = unpack("<b2hhi", d)
    echo "125 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # !B?bqBh
    let d = pack("!B?bqBh", uint8(1), false, int8(-87), int64(-5793224303848145812), uint8(53), int16(1))
    echo "126 ", hxb(d), " ", calcsize("!B?bqBh")
    let t = unpack("!B?bqBh", d)
    echo "126 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # !d3H3xQ2l
    let d = pack("!d3H3xQ2l", cast[float64](0xfe37e43c8800759c'u64), uint16(3178), uint16(1), uint16(8276), uint64(6309118946414723765'u64), int32(-2147483648), int32(265966824))
    echo "127 ", hxb(d), " ", calcsize("!d3H3xQ2l")
    let t = unpack("!d3H3xQ2l", d)
    echo "127 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # I2Lne
    let d = pack("I2Lne", uint32(1101167398), culong(14115778729601217220'u64), culong(7446341428154255053'u64), int(-2820414064452046565), cast[float64](0x408fd20000000000'u64))
    echo "128 ", hxb(d), " ", calcsize("I2Lne")
    let t = unpack("I2Lne", d)
    echo "128 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # @QddP3cP
    let d = pack("@QddP3cP", uint64(501575716741718759'u64), cast[float64](0x3fb999999999999a'u64), cast[float64](0x3fb999999999999a'u64), uint(1'u64), char(21), char(130), char(99), uint(1887868781385150257'u64))
    echo "129 ", hxb(d), " ", calcsize("@QddP3cP")
    let t = unpack("@QddP3cP", d)
    echo "129 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7])
  block:  # !cd?4sL
    let d = pack("!cd?4sL", char(110), cast[float64](0xfff0000000000000'u64), false, "\x41\x7e\x8c\x98\x5a", uint32(1))
    echo "130 ", hxb(d), " ", calcsize("!cd?4sL")
    let t = unpack("!cd?4sL", d)
    echo "130 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # !2i5sLQb3h
    let d = pack("!2i5sLQb3h", int32(-813337347), int32(0), "\x1d\xdf", uint32(3301294524), uint64(17403123165729829754'u64), int8(123), int16(0), int16(32767), int16(-2791))
    echo "131 ", hxb(d), " ", calcsize("!2i5sLQb3h")
    let t = unpack("!2i5sLQb3h", d)
    echo "131 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7]), " ", show(t[8])
  block:  # >B3sL3hBc
    let d = pack(">B3sL3hBc", uint8(0), "\x1d\xaa\x37", uint32(1), int16(-32768), int16(-26181), int16(-29), uint8(0), char(123))
    echo "132 ", hxb(d), " ", calcsize(">B3sL3hBc")
    let t = unpack(">B3sL3hBc", d)
    echo "132 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7])
  block:  # =2Qq4p
    let d = pack("=2Qq4p", uint64(18446744073709551615'u64), uint64(17691624389614896006'u64), int64(1), "\xd4\x80\xd6")
    echo "133 ", hxb(d), " ", calcsize("=2Qq4p")
    let t = unpack("=2Qq4p", d)
    echo "133 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # <2b3?Lc2f
    let d = pack("<2b3?Lc2f", int8(-29), int8(-100), true, true, false, uint32(2641384044), char(65), cast[float32](0x000116c2'u32), cast[float32](0xc0200000'u32))
    echo "134 ", hxb(d), " ", calcsize("<2b3?Lc2f")
    let t = unpack("<2b3?Lc2f", d)
    echo "134 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7]), " ", show(t[8])
  block:  # =i2e3i2QQB
    let d = pack("=i2e3i2QQB", int32(1), cast[float64](0x40ec842d032717ca'u64), cast[float64](0x8000000000000000'u64), int32(330668212), int32(-1324640106), int32(-2147483648), uint64(3819293858803033955'u64), uint64(8356886630856370896'u64), uint64(430250640773736006'u64), uint8(45))
    echo "135 ", hxb(d), " ", calcsize("=i2e3i2QQB")
    let t = unpack("=i2e3i2QQB", d)
    echo "135 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7]), " ", show(t[8]), " ", show(t[9])
  block:  # =d4pQ6sQb
    let d = pack("=d4pQ6sQb", cast[float64](0xc1b849bd44ca4bf0'u64), "\xe8\xde\x6c\x98", uint64(0'u64), "\xae\xc8\x08\xd5\xb0\xda\x84\x2e", uint64(15934445475039355550'u64), int8(127))
    echo "136 ", hxb(d), " ", calcsize("=d4pQ6sQb")
    let t = unpack("=d4pQ6sQb", d)
    echo "136 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # ccPn
    let d = pack("ccPn", char(173), char(186), uint(10353974630869146778'u64), int(-8757490500452157007))
    echo "137 ", hxb(d), " ", calcsize("ccPn")
    let t = unpack("ccPn", d)
    echo "137 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # @0sIL
    let d = pack("@0sIL", "\xa7", uint32(1), culong(8492179573181977253'u64))
    echo "138 ", hxb(d), " ", calcsize("@0sIL")
    let t = unpack("@0sIL", d)
    echo "138 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # @fl3c6ph
    let d = pack("@fl3c6ph", cast[float32](0x000116c2'u32), clong(251814665016722814), char(191), char(203), char(207), "\x9f\x7f", int16(-32768))
    echo "139 ", hxb(d), " ", calcsize("@fl3c6ph")
    let t = unpack("@fl3c6ph", d)
    echo "139 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # >3xc5x
    let d = pack(">3xc5x", char(149))
    echo "140 ", hxb(d), " ", calcsize(">3xc5x")
    let t = unpack(">3xc5x", d)
    echo "140 ", show(t)
  block:  # !qL
    let d = pack("!qL", int64(-8713416081528627929), uint32(1542488683))
    echo "141 ", hxb(d), " ", calcsize("!qL")
    let t = unpack("!qL", d)
    echo "141 ", show(t[0]), " ", show(t[1])
  block:  # @N?
    let d = pack("@N?", uint(14089815482166186127'u64), false)
    echo "142 ", hxb(d), " ", calcsize("@N?")
    let t = unpack("@N?", d)
    echo "142 ", show(t[0]), " ", show(t[1])
  block:  # !qLicc
    let d = pack("!qLicc", int64(-7466953596366455216), uint32(0), int32(-487226730), char(52), char(213))
    echo "143 ", hxb(d), " ", calcsize("!qLicc")
    let t = unpack("!qLicc", d)
    echo "143 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # <hc3Liq1x
    let d = pack("<hc3Liq1x", int16(6517), char(133), uint32(0), uint32(2542731542), uint32(0), int32(-2147483648), int64(-5719738804948707595))
    echo "144 ", hxb(d), " ", calcsize("<hc3Liq1x")
    let t = unpack("<hc3Liq1x", d)
    echo "144 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # @f1seqf
    let d = pack("@f1seqf", cast[float32](0xc0200000'u32), "\x0b\x97", cast[float64](0x4020500000000000'u64), int64(1), cast[float32](0xc0200000'u32))
    echo "145 ", hxb(d), " ", calcsize("@f1seqf")
    let t = unpack("@f1seqf", d)
    echo "145 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # !f2f2H3p4p
    let d = pack("!f2f2H3p4p", cast[float32](0x7f7fc99e'u32), cast[float32](0x7f7fc99e'u32), cast[float32](0x3dcccccd'u32), uint16(14765), uint16(65535), "\x38\xe5\xde", "\x1c\x58\x23\xed")
    echo "146 ", hxb(d), " ", calcsize("!f2f2H3p4p")
    let t = unpack("!f2f2H3p4p", d)
    echo "146 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # df
    let d = pack("df", cast[float64](0x41c29f0033688340'u64), cast[float32](0x494de64a'u32))
    echo "147 ", hxb(d), " ", calcsize("df")
    let t = unpack("df", d)
    echo "147 ", show(t[0]), " ", show(t[1])
  block:  # <i
    let d = pack("<i", int32(446693232))
    echo "148 ", hxb(d), " ", calcsize("<i")
    let t = unpack("<i", d)
    echo "148 ", show(t)
  block:  # >2Lhi
    let d = pack(">2Lhi", uint32(0), uint32(3073582126), int16(-28847), int32(1659851271))
    echo "149 ", hxb(d), " ", calcsize(">2Lhi")
    let t = unpack(">2Lhi", d)
    echo "149 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # IhB
    let d = pack("IhB", uint32(2418823005), int16(300), uint8(94))
    echo "150 ", hxb(d), " ", calcsize("IhB")
    let t = unpack("IhB", d)
    echo "150 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # =cIHb
    let d = pack("=cIHb", char(121), uint32(2970373678), uint16(41935), int8(-98))
    echo "151 ", hxb(d), " ", calcsize("=cIHb")
    let t = unpack("=cIHb", d)
    echo "151 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # =3Q3cq2Q
    let d = pack("=3Q3cq2Q", uint64(0'u64), uint64(4406459938116718754'u64), uint64(0'u64), char(39), char(17), char(66), int64(1), uint64(1'u64), uint64(2725085337178948601'u64))
    echo "152 ", hxb(d), " ", calcsize("=3Q3cq2Q")
    let t = unpack("=3Q3cq2Q", d)
    echo "152 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7]), " ", show(t[8])
  block:  # >ci2Q?c
    let d = pack(">ci2Q?c", char(117), int32(2147483647), uint64(3699539501842830415'u64), uint64(1303102600270901407'u64), false, char(209))
    echo "153 ", hxb(d), " ", calcsize(">ci2Q?c")
    let t = unpack(">ci2Q?c", d)
    echo "153 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # >0s3Qc1x
    let d = pack(">0s3Qc1x", "\x04", uint64(2959665284250588877'u64), uint64(753779257312788125'u64), uint64(0'u64), char(125))
    echo "154 ", hxb(d), " ", calcsize(">0s3Qc1x")
    let t = unpack(">0s3Qc1x", d)
    echo "154 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # <hLBBqI
    let d = pack("<hLBBqI", int16(2567), uint32(617314976), uint8(46), uint8(0), int64(-4064007879598108220), uint32(2606315187))
    echo "155 ", hxb(d), " ", calcsize("<hLBBqI")
    let t = unpack("<hLBBqI", d)
    echo "155 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # >f2xh
    let d = pack(">f2xh", cast[float32](0xc0200000'u32), int16(1678))
    echo "156 ", hxb(d), " ", calcsize(">f2xh")
    let t = unpack(">f2xh", d)
    echo "156 ", show(t[0]), " ", show(t[1])
  block:  # >5pL2BL
    let d = pack(">5pL2BL", "\x0d\x21\xdc\x77\xf6\x5b\xed", uint32(1807942083), uint8(203), uint8(1), uint32(2657458122))
    echo "157 ", hxb(d), " ", calcsize(">5pL2BL")
    let t = unpack(">5pL2BL", d)
    echo "157 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # ?h
    let d = pack("?h", false, int16(-8748))
    echo "158 ", hxb(d), " ", calcsize("?h")
    let t = unpack("?h", d)
    echo "158 ", show(t[0]), " ", show(t[1])
  block:  # @Hqc3cIq
    let d = pack("@Hqc3cIq", uint16(0), int64(6506967825995788310), char(82), char(178), char(65), char(47), uint32(516839590), int64(-3196922803390397939))
    echo "159 ", hxb(d), " ", calcsize("@Hqc3cIq")
    let t = unpack("@Hqc3cIq", d)
    echo "159 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7])
  block:  # =e3xd
    let d = pack("=e3xd", cast[float64](0x3ff8000000000000'u64), cast[float64](0xfe37e43c8800759c'u64))
    echo "160 ", hxb(d), " ", calcsize("=e3xd")
    let t = unpack("=e3xd", d)
    echo "160 ", show(t[0]), " ", show(t[1])
  block:  # !q3lIdd
    let d = pack("!q3lIdd", int64(low(int64)), int32(1), int32(1946198394), int32(295711427), uint32(4294967295), cast[float64](0xfff0000000000000'u64), cast[float64](0x0000000000000001'u64))
    echo "161 ", hxb(d), " ", calcsize("!q3lIdd")
    let t = unpack("!q3lIdd", d)
    echo "161 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # !H1x2d2?
    let d = pack("!H1x2d2?", uint16(20287), cast[float64](0xfff0000000000000'u64), cast[float64](0x3fb999999999999a'u64), false, true)
    echo "162 ", hxb(d), " ", calcsize("!H1x2d2?")
    let t = unpack("!H1x2d2?", d)
    echo "162 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # !?2bLHhl
    let d = pack("!?2bLHhl", false, int8(-128), int8(-48), uint32(2654502676), uint16(54623), int16(-27428), int32(-1122705195))
    echo "163 ", hxb(d), " ", calcsize("!?2bLHhl")
    let t = unpack("!?2bLHhl", d)
    echo "163 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # @3p3ihIL
    let d = pack("@3p3ihIL", "\x72\xed\x20\x3c\x30", int32(2147483647), int32(620495639), int32(-562914607), int16(32767), uint32(1), culong(18067380515865507207'u64))
    echo "164 ", hxb(d), " ", calcsize("@3p3ihIL")
    let t = unpack("@3p3ihIL", d)
    echo "164 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # =Bq3p
    let d = pack("=Bq3p", uint8(78), int64(-4588863816155075305), "\x33\x58")
    echo "165 ", hxb(d), " ", calcsize("=Bq3p")
    let t = unpack("=Bq3p", d)
    echo "165 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # !Q?5sbd
    let d = pack("!Q?5sbd", uint64(12903198046469307058'u64), true, "\xd9\x8e\x9c\xf5", int8(0), cast[float64](0x3fb999999999999a'u64))
    echo "166 ", hxb(d), " ", calcsize("!Q?5sbd")
    let t = unpack("!Q?5sbd", d)
    echo "166 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # <2bidc
    let d = pack("<2bidc", int8(4), int8(56), int32(-1617364024), cast[float64](0x3fb999999999999a'u64), char(90))
    echo "167 ", hxb(d), " ", calcsize("<2bidc")
    let t = unpack("<2bidc", d)
    echo "167 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # @BhhLlf
    let d = pack("@BhhLlf", uint8(160), int16(-12059), int16(21432), culong(8205612774345217383'u64), clong(-3512969024978525311), cast[float32](0x000116c2'u32))
    echo "168 ", hxb(d), " ", calcsize("@BhhLlf")
    let t = unpack("@BhhLlf", d)
    echo "168 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # >I3L3eb3H
    let d = pack(">I3L3eb3H", uint32(781111230), uint32(2810150220), uint32(178793094), uint32(1), cast[float64](0x8000000000000000'u64), cast[float64](0x8000000000000000'u64), cast[float64](0x8000000000000000'u64), int8(97), uint16(1), uint16(27344), uint16(47909))
    echo "169 ", hxb(d), " ", calcsize(">I3L3eb3H")
    let t = unpack(">I3L3eb3H", d)
    echo "169 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7]), " ", show(t[8]), " ", show(t[9]), " ", show(t[10])
  block:  # >ibd3q
    let d = pack(">ibd3q", int32(1185833172), int8(105), cast[float64](0x0000000000000001'u64), int64(6934903513438178060), int64(-6547887053770742920), int64(1))
    echo "170 ", hxb(d), " ", calcsize(">ibd3q")
    let t = unpack(">ibd3q", d)
    echo "170 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # @cei
    let d = pack("@cei", char(15), cast[float64](0x0000000000000000'u64), int32(-1558708243))
    echo "171 ", hxb(d), " ", calcsize("@cei")
    let t = unpack("@cei", d)
    echo "171 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # @N3h3x2i3Hd
    let d = pack("@N3h3x2i3Hd", uint(812082268620742650'u64), int16(-21089), int16(1536), int16(-24373), int32(433776151), int32(1881214541), uint16(0), uint16(65535), uint16(0), cast[float64](0x3fb999999999999a'u64))
    echo "172 ", hxb(d), " ", calcsize("@N3h3x2i3Hd")
    let t = unpack("@N3h3x2i3Hd", d)
    echo "172 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7]), " ", show(t[8]), " ", show(t[9])
  block:  # @Le0sclQ
    let d = pack("@Le0sclQ", culong(7666843748769324163'u64), cast[float64](0x7ff0000000000000'u64), "\xe0", char(116), clong(-8285225814574621397), uint64(5385572748793305592'u64))
    echo "173 ", hxb(d), " ", calcsize("@Le0sclQ")
    let t = unpack("@Le0sclQ", d)
    echo "173 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # @lfL2Q2x
    let d = pack("@lfL2Q2x", clong(-7103530574358661612), cast[float32](0x000116c2'u32), culong(16213680744472562865'u64), uint64(444035297674237979'u64), uint64(1'u64))
    echo "174 ", hxb(d), " ", calcsize("@lfL2Q2x")
    let t = unpack("@lfL2Q2x", d)
    echo "174 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # <Q3s?
    let d = pack("<Q3s?", uint64(16387049896148114771'u64), "\xf3\x43\xc0\x03", true)
    echo "175 ", hxb(d), " ", calcsize("<Q3s?")
    let t = unpack("<Q3s?", d)
    echo "175 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # @?3d2e
    let d = pack("@?3d2e", false, cast[float64](0x0000000000000001'u64), cast[float64](0xfff0000000000000'u64), cast[float64](0x3fb999999999999a'u64), cast[float64](0x40effc0000000000'u64), cast[float64](0x0000000000000000'u64))
    echo "176 ", hxb(d), " ", calcsize("@?3d2e")
    let t = unpack("@?3d2e", d)
    echo "176 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # @3f?0sh
    let d = pack("@3f?0sh", cast[float32](0x000116c2'u32), cast[float32](0xc0200000'u32), cast[float32](0x3dcccccd'u32), true, "\x7d\x65", int16(30436))
    echo "177 ", hxb(d), " ", calcsize("@3f?0sh")
    let t = unpack("@3f?0sh", d)
    echo "177 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # @ql1xbcB
    let d = pack("@ql1xbcB", int64(6902940784233581644), clong(8611977792001267069), int8(113), char(65), uint8(138))
    echo "178 ", hxb(d), " ", calcsize("@ql1xbcB")
    let t = unpack("@ql1xbcB", d)
    echo "178 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # @L2?hBe
    let d = pack("@L2?hBe", culong(12553785020291089005'u64), true, true, int16(31185), uint8(1), cast[float64](0x3ff8000000000000'u64))
    echo "179 ", hxb(d), " ", calcsize("@L2?hBe")
    let t = unpack("@L2?hBe", d)
    echo "179 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # 2qQQ3H
    let d = pack("2qQQ3H", int64(3981891154870600371), int64(1), uint64(4182806457740961775'u64), uint64(1'u64), uint16(17559), uint16(2713), uint16(22746))
    echo "180 ", hxb(d), " ", calcsize("2qQQ3H")
    let t = unpack("2qQQ3H", d)
    echo "180 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # 2NLq
    let d = pack("2NLq", uint(0'u64), uint(11777573881891945482'u64), culong(6749866155713155622'u64), int64(0))
    echo "181 ", hxb(d), " ", calcsize("2NLq")
    let t = unpack("2NLq", d)
    echo "181 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # @dcHP
    let d = pack("@dcHP", cast[float64](0x0000000000000001'u64), char(179), uint16(1), uint(10620934548347108091'u64))
    echo "182 ", hxb(d), " ", calcsize("@dcHP")
    let t = unpack("@dcHP", d)
    echo "182 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # 3BqLH
    let d = pack("3BqLH", uint8(166), uint8(0), uint8(149), int64(-8016705311423771141), culong(15983934158022031772'u64), uint16(7242))
    echo "183 ", hxb(d), " ", calcsize("3BqLH")
    let t = unpack("3BqLH", d)
    echo "183 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # !i5p
    let d = pack("!i5p", int32(-2147483648), "\xed\x44\xc4\xa0\x89\x1e\xe1")
    echo "184 ", hxb(d), " ", calcsize("!i5p")
    let t = unpack("!i5p", d)
    echo "184 ", show(t[0]), " ", show(t[1])
  block:  # <he
    let d = pack("<he", int16(-5343), cast[float64](0x40d0320000000000'u64))
    echo "185 ", hxb(d), " ", calcsize("<he")
    let t = unpack("<he", d)
    echo "185 ", show(t[0]), " ", show(t[1])
  block:  # !b
    let d = pack("!b", int8(-64))
    echo "186 ", hxb(d), " ", calcsize("!b")
    let t = unpack("!b", d)
    echo "186 ", show(t)
  block:  # >4s6x3?ffc
    let d = pack(">4s6x3?ffc", "", false, true, false, cast[float32](0x000116c2'u32), cast[float32](0xc8a6bc07'u32), char(64))
    echo "187 ", hxb(d), " ", calcsize(">4s6x3?ffc")
    let t = unpack(">4s6x3?ffc", d)
    echo "187 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # =6sIlQH
    let d = pack("=6sIlQH", "\x2e", uint32(2529843486), int32(2147483647), uint64(11294510917623220954'u64), uint16(38801))
    echo "188 ", hxb(d), " ", calcsize("=6sIlQH")
    let t = unpack("=6sIlQH", d)
    echo "188 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # !b?
    let d = pack("!b?", int8(1), false)
    echo "189 ", hxb(d), " ", calcsize("!b?")
    let t = unpack("!b?", d)
    echo "189 ", show(t[0]), " ", show(t[1])
  block:  # !LHBq0s
    let d = pack("!LHBq0s", uint32(4294967295), uint16(65535), uint8(255), int64(7668181006923537721), "")
    echo "190 ", hxb(d), " ", calcsize("!LHBq0s")
    let t = unpack("!LHBq0s", d)
    echo "190 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # @c3H3cb
    let d = pack("@c3H3cb", char(23), uint16(1), uint16(65535), uint16(0), char(28), char(64), char(226), int8(0))
    echo "191 ", hxb(d), " ", calcsize("@c3H3cb")
    let t = unpack("@c3H3cb", d)
    echo "191 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7])
  block:  # =i
    let d = pack("=i", int32(-1008180624))
    echo "192 ", hxb(d), " ", calcsize("=i")
    let t = unpack("=i", d)
    echo "192 ", show(t)
  block:  # @Qfd3Hi
    let d = pack("@Qfd3Hi", uint64(0'u64), cast[float32](0x3dcccccd'u32), cast[float64](0x3fb999999999999a'u64), uint16(60643), uint16(51083), uint16(30963), int32(1))
    echo "193 ", hxb(d), " ", calcsize("@Qfd3Hi")
    let t = unpack("@Qfd3Hi", d)
    echo "193 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # @1x?
    let d = pack("@1x?", false)
    echo "194 ", hxb(d), " ", calcsize("@1x?")
    let t = unpack("@1x?", d)
    echo "194 ", show(t)
  block:  # @2e?4xI
    let d = pack("@2e?4xI", cast[float64](0x3ff8000000000000'u64), cast[float64](0x7ff0000000000000'u64), true, uint32(2846651381))
    echo "195 ", hxb(d), " ", calcsize("@2e?4xI")
    let t = unpack("@2e?4xI", d)
    echo "195 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # >H3Hd?
    let d = pack(">H3Hd?", uint16(38391), uint16(35605), uint16(8334), uint16(19109), cast[float64](0x419a450b256aeb20'u64), true)
    echo "196 ", hxb(d), " ", calcsize(">H3Hd?")
    let t = unpack(">H3Hd?", d)
    echo "196 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # !bdbf
    let d = pack("!bdbf", int8(-66), cast[float64](0xfff0000000000000'u64), int8(106), cast[float32](0xc0200000'u32))
    echo "197 ", hxb(d), " ", calcsize("!bdbf")
    let t = unpack("!bdbf", d)
    echo "197 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # <b2Bb6ph
    let d = pack("<b2Bb6ph", int8(-104), uint8(0), uint8(69), int8(4), "\x17\x6f", int16(20854))
    echo "198 ", hxb(d), " ", calcsize("<b2Bb6ph")
    let t = unpack("<b2Bb6ph", d)
    echo "198 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # @d3x
    let d = pack("@d3x", cast[float64](0xfff0000000000000'u64))
    echo "199 ", hxb(d), " ", calcsize("@d3x")
    let t = unpack("@d3x", d)
    echo "199 ", show(t)
  block:  # >2xLH2s3pI
    let d = pack(">2xLH2s3pI", uint32(4294967295), uint16(45312), "\x0d", "\x13\x9e", uint32(3312388824))
    echo "200 ", hxb(d), " ", calcsize(">2xLH2s3pI")
    let t = unpack(">2xLH2s3pI", d)
    echo "200 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # @i2Bfq6x
    let d = pack("@i2Bfq6x", int32(502035185), uint8(0), uint8(1), cast[float32](0xc0200000'u32), int64(-2454725601355220394))
    echo "201 ", hxb(d), " ", calcsize("@i2Bfq6x")
    let t = unpack("@i2Bfq6x", d)
    echo "201 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # =3p4s
    let d = pack("=3p4s", "\x12\x57\x78\x95", "")
    echo "202 ", hxb(d), " ", calcsize("=3p4s")
    let t = unpack("=3p4s", d)
    echo "202 ", show(t[0]), " ", show(t[1])
  block:  # @l3l3s2d
    let d = pack("@l3l3s2d", clong(-9085824673240971844), clong(5241873812104473655), clong(-5251044107799733107), clong(2145112449381638515), "\x6a\x93\x9d\xbe", cast[float64](0xfff0000000000000'u64), cast[float64](0x41bbf61880ddb85c'u64))
    echo "203 ", hxb(d), " ", calcsize("@l3l3s2d")
    let t = unpack("@l3l3s2d", d)
    echo "203 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6])
  block:  # >?dL
    let d = pack(">?dL", false, cast[float64](0x3fb999999999999a'u64), uint32(4294967295))
    echo "204 ", hxb(d), " ", calcsize(">?dL")
    let t = unpack(">?dL", d)
    echo "204 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # =d3p3pb6pc
    let d = pack("=d3p3pb6pc", cast[float64](0xfff0000000000000'u64), "\x55\xc8\xb7\x98\x54", "", int8(-38), "\x57\x71", char(149))
    echo "205 ", hxb(d), " ", calcsize("=d3p3pb6pc")
    let t = unpack("=d3p3pb6pc", d)
    echo "205 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5])
  block:  # <2f3fhqBd
    let d = pack("<2f3fhqBd", cast[float32](0xc9726854'u32), cast[float32](0x7f7fc99e'u32), cast[float32](0xc91822df'u32), cast[float32](0x7f7fc99e'u32), cast[float32](0x47b959b4'u32), int16(32767), int64(-115266982433424294), uint8(106), cast[float64](0xfff0000000000000'u64))
    echo "206 ", hxb(d), " ", calcsize("<2f3fhqBd")
    let t = unpack("<2f3fhqBd", d)
    echo "206 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4]), " ", show(t[5]), " ", show(t[6]), " ", show(t[7]), " ", show(t[8])
  block:  # !Idh6pL
    let d = pack("!Idh6pL", uint32(4239340667), cast[float64](0x0000000000000001'u64), int16(1894), "\xe0\xc9\xcd\xd8\x49\xde", uint32(4080149552))
    echo "207 ", hxb(d), " ", calcsize("!Idh6pL")
    let t = unpack("!Idh6pL", d)
    echo "207 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # b2B
    let d = pack("b2B", int8(13), uint8(90), uint8(53))
    echo "208 ", hxb(d), " ", calcsize("b2B")
    let t = unpack("b2B", d)
    echo "208 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # =h
    let d = pack("=h", int16(18518))
    echo "209 ", hxb(d), " ", calcsize("=h")
    let t = unpack("=h", d)
    echo "209 ", show(t)
  block:  # !dici
    let d = pack("!dici", cast[float64](0x3fb999999999999a'u64), int32(-310638818), char(114), int32(1))
    echo "210 ", hxb(d), " ", calcsize("!dici")
    let t = unpack("!dici", d)
    echo "210 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3])
  block:  # =ib3c
    let d = pack("=ib3c", int32(-1171028980), int8(6), char(16), char(170), char(123))
    echo "211 ", hxb(d), " ", calcsize("=ib3c")
    let t = unpack("=ib3c", d)
    echo "211 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # =HhB2B
    let d = pack("=HhB2B", uint16(0), int16(25737), uint8(236), uint8(118), uint8(101))
    echo "212 ", hxb(d), " ", calcsize("=HhB2B")
    let t = unpack("=HhB2B", d)
    echo "212 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # 1s6xBb
    let d = pack("1s6xBb", "\x81", uint8(0), int8(103))
    echo "213 ", hxb(d), " ", calcsize("1s6xBb")
    let t = unpack("1s6xBb", d)
    echo "213 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # !d
    let d = pack("!d", cast[float64](0xfff0000000000000'u64))
    echo "214 ", hxb(d), " ", calcsize("!d")
    let t = unpack("!d", d)
    echo "214 ", show(t)
  block:  # e6sq
    let d = pack("e6sq", cast[float64](0x3f16aa0000000000'u64), "\x99\x4b\xea\x81\xce\x09\x7e", int64(762626761225541509))
    echo "215 ", hxb(d), " ", calcsize("e6sq")
    let t = unpack("e6sq", d)
    echo "215 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # @6pBN
    let d = pack("@6pBN", "\xdb\xf5\x28\xb5", uint8(0), uint(17792575073218953887'u64))
    echo "216 ", hxb(d), " ", calcsize("@6pBN")
    let t = unpack("@6pBN", d)
    echo "216 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # !6xdc2f6x6s
    let d = pack("!6xdc2f6x6s", cast[float64](0xfff0000000000000'u64), char(8), cast[float32](0x4912ad1d'u32), cast[float32](0xc919b14a'u32), "\x72\x22")
    echo "217 ", hxb(d), " ", calcsize("!6xdc2f6x6s")
    let t = unpack("!6xdc2f6x6s", d)
    echo "217 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # >6sdd
    let d = pack(">6sdd", "\xbb\x66\x2a\x7e\x34\x23\x93\x7f", cast[float64](0xfe37e43c8800759c'u64), cast[float64](0x419787680d750bc0'u64))
    echo "218 ", hxb(d), " ", calcsize(">6sdd")
    let t = unpack(">6sdd", d)
    echo "218 ", show(t[0]), " ", show(t[1]), " ", show(t[2])
  block:  # !2i?Lb
    let d = pack("!2i?Lb", int32(1099150357), int32(2026185450), false, uint32(1216909886), int8(0))
    echo "219 ", hxb(d), " ", calcsize("!2i?Lb")
    let t = unpack("!2i?Lb", d)
    echo "219 ", show(t[0]), " ", show(t[1]), " ", show(t[2]), " ", show(t[3]), " ", show(t[4])
  block:  # =5pe
    let d = pack("=5pe", "", cast[float64](0x402e7a0000000000'u64))
    echo "220 ", hxb(d), " ", calcsize("=5pe")
    let t = unpack("=5pe", d)
    echo "220 ", show(t[0]), " ", show(t[1])
try: main()
except ErrorCode as e: echo "error ", $e
