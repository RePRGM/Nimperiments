import ../../src/binstruct
proc f() {.raises.} =
  let buf: seq[byte] = @[]
  var r = initReader(buf)
  var x = 5
  discard unpack("<hz", buf)
