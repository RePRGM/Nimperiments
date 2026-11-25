import std/syncio
import ../src/binstruct

proc main() {.raises.} =
  let buf: seq[byte] = @[1'u8, 0, 2, 0, 3, 0, 0, 0]
  let (a, b, c) = unpack("<HHI", buf)
  echo a, " ", b, " ", c, " ", typeof(c) is uint32
  let one = unpack("<I", "\x2a\x00\x00\x00")
  echo one
  let arr = pack(">HHI", 1, 2, 300)
  echo arr.len, " ", arr[7]
  echo calcsize("<HHI"), " ", calcsize("@bhiq")
try: main()
except ErrorCode as e: echo "error ", $e
