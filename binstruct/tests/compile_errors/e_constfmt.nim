import ../../src/binstruct
proc f() {.raises.} =
  let buf: seq[byte] = @[]
  var r = initReader(buf)
  var x = 5
  const F = "<H"; discard unpack(F, buf)
