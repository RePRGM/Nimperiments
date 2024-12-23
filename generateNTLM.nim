# AI Generated

import hashlib/rhash/md4
from strutils import toUpperAscii

proc toUtf16LE(s: string): seq[uint8] =
  result = newSeq[uint8](s.len * 2)
  var j = 0
  for i in 0 ..< s.len:
    result[j] = uint8(s[i])
    result[j + 1] = 0
    j += 2

proc generateNTLMHash(password: string): string =
  # Convert password to UTF-16LE
  let utf16password = toUtf16LE(password)
  
  # Use the stream API for MD4
  var ctx = init[RHASH_MD4]()
  ctx.update(utf16password)
  let hash = ctx.final()
  
  # Convert to uppercase hex string
  result = ($hash).toUpperAscii()

# Example Usage
when isMainModule:
    echo generateNTLMHash("password")
