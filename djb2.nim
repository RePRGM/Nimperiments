import os
import strformat

let args = commandLineParams()
let strToHash = args[0]

proc djb2Hash(s: string): uint =
  # Initialize the hash value to 5381
  var hash: uint = 5381

  # Iterate through the string and update the hash value
  for c in s:
    hash = ((hash shl 5) + hash) xor uint(c)

  # Return the hash value
  return hash

echo fmt"{strToHash} : {djb2Hash(strToHash)}"
