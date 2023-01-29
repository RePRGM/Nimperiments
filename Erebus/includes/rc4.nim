# Stolen from Nim RC4 Module
# SystemFunction032 "stolen" from @securethisshit

import strutils
import winim

#Decrypt
proc SystemFunction032*(memoryRegion: pointer, keyPointer: pointer): NTSTATUS 
  {.discardable, stdcall, dynlib: "Advapi32", importc: "SystemFunction032".}

proc genKeystream(key: string): array[256, int] =
  for i in 0..255:
    result[i] = i
  var j, k = 0
  for i in 0..255:
    j = (j + result[i] + ord(key[k])) mod 256
    swap(result[i], result[j])
    k = (k + 1) mod key.len

iterator iterate(keystream: var array[256, int],
                size: int, incr = 1): tuple[i, j, k: int] =
  var i, j, k = 0
  while i < size:
    j = (j + 1) mod 256
    k = (k + keystream[j]) mod 256
    swap(keystream[k], keystream[j])
    yield (i, j, k)
    i += incr

proc toRC4*(key, data: string): string =
  var keyst = genKeystream(key)

  for i, j, k in iterate(keyst, data.len):
    result.add((ord(data[i]) xor keyst[(keyst[j] +
                keyst[k]) mod 256]).toHex(2))

proc fromRC4*(key, data: string): string =
  var keyst = genKeystream(key)

  for i, j, k in iterate(keyst, data.len, 2):
    result.add((fromHex[int](data[i] & data[i+1]) xor
                keyst[(keyst[j] + keyst[k]) mod 256]).char)
