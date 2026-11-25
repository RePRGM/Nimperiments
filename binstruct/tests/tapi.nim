import std/syncio
import ../src/binstruct

func hxb(a: openArray[byte]): string =
  const d = "0123456789abcdef"
  result = ""
  for b in a:
    result.add d[int(b shr 4)]
    result.add d[int(b and 15)]

proc tryErr(label: string; code: ErrorCode) = echo label, " ", $code

proc apiTests() {.raises.} =
  # unpackFrom, positive and negative offsets
  let raw = "\x00\x01\x02\x03\x04\x05"
  echo "A ", unpackFrom(">H", raw, 2), " ", unpackFrom(">H", raw, -2)
  # packInto: seq, string, array
  var s = newSeq[byte](8)
  packInto("<HI", s, 1, 0x1234, 0xdeadbeef'u32)
  echo "B ", hxb(s)
  var str = "........"
  packInto(">H", str, 6, 0x4142)
  echo "C ", str
  var arr = default(array[4, byte])
  packInto("!h", arr, 0, -2)
  echo "D ", hxb(arr)

  # stream writer: NDR alignment relative to base, runtime order
  var w = initWriter(boBig)
  writeFmt(w, "BIH", 1, 2, 3)          # B, pad3, I, H
  writeFmt(w, "Q", 4)                   # pad to 8
  writeFmt(w, "<H", 5)                  # fixed LE, packed
  writeFmt(w, "=I", 6)                  # stream order, packed (no align)
  writeFmt(w, "4s", "ab")
  echo "E ", hxb(w.data), " ", w.len
  # read it back with the same rules
  var r = initReader(w.data, boBig)
  let (b, i, h) = readFmt(r, "BIH")
  let q = readFmt(r, "Q")
  let le = readFmt(r, "<H")
  let packed = readFmt(r, "=I")
  let tag = readFmt(r, "4s")
  echo "F ", b, " ", i, " ", h, " ", q, " ", le, " ", packed, " ", tag[0], tag[1], tag[2], " ", r.atEnd
  # patch a length field after the fact
  var w2 = initWriter(boLittle)
  writeFmt(w2, "HH", 0xaaaa, 0)       # second H is a placeholder
  w2.writeBytes("payload")
  patchFmt(w2, "H", 2, uint16(w2.len))
  echo "G ", hxb(w2.data)
  # sub-reader keeps alignment origin of the parent
  var r3 = initReader("\x01\x00\x00\x00\x02\x00\x00\x00", boLittle)
  discard readFmt(r3, "B")
  var inner = r3.sub(7)
  echo "H ", readFmt(inner, "I"), " ", inner.atEnd

proc errorTests() =
  try:
    discard unpack("<I", "abc")
    echo "no error"
  except ErrorCode as e: tryErr("E1 unpack short", e)
  try:
    discard unpackFrom("<I", "abcdef", 3)
    echo "no error"
  except ErrorCode as e: tryErr("E2 unpackFrom past end", e)
  try:
    var s = newSeq[byte](3)
    packInto("<I", s, 0, 1'u32)
    echo "no error"
  except ErrorCode as e: tryErr("E3 packInto short", e)
  try:
    discard pack("<e", 70000.0)
    echo "no error"
  except ErrorCode as e: tryErr("E4 half overflow", e)
  try:
    var r = initReader("\x01\x02\x03", boLittle)
    discard readFmt(r, "B")
    discard readFmt(r, "H")      # aligned to 2 -> starts at 2, needs 4 bytes
    echo "no error"
  except ErrorCode as e: tryErr("E5 reader short", e)

try: apiTests()
except ErrorCode as e: echo "unexpected ", $e
errorTests()
