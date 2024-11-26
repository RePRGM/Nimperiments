import winim

proc hashStrA*(s: cstring): uint32 {.inline.} =
  var hash: uint32 = 0xff
  for i in s: hash = ((hash shl 5) + hash) + cast[uint32](i)
  return hash

proc hashStrW*(s: PWSTR): uint32  =
  var 
    hash: uint32 = 0xff
    pS = cast[ptr UncheckedArray[WCHAR]](s)
    idx: int = 0
  while pS[idx] != 0:
    hash = ((hash shl 5) + hash) + cast[uint32](pS[idx])
    idx.inc
  return hash
