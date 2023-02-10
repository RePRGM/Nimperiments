# Stolen from https://www.stevencampbell.info/Nim-Convert-Shellcode-to-UUID/
import std/[strutils, sugar, algorithm]
import sequtils
import os

# Stolen from https://github.com/narimiran/itertools/blob/master/src/itertools.nim
iterator chunked*[T](s: openArray[T], size: Positive): seq[T] =
  ## Iterator which yields ``size``-sized chunks from ``s``.
  var i: int
  while i + size < len(s):
    yield s[i ..< i+size]
    i += size
  yield s[i .. ^1]

proc convertToUuid*(sc: string): (int, seq[string]) =
    ## This proc takes a string and outputs a sequence of UUID's
    var sc_seq = collect(for x in sc.chunked(2): x.join(""))
    # check if shellcode len evenly divisible by 16 and pad with nops as required
    if len(sc_seq) mod 16 != 0:
        var padding: int = 16 - (len(sc_seq) mod 16)
        for x in 0..<padding:
            sc_seq = "90" & sc_seq
    # break up sc_seq into 16 byte chunks
    let chunks = len(sc_seq) div 16
    var seqOfSeqs = sc_seq.distribute(chunks)
    # construct UUID's
    var uuids: seq[string]
    for sequence in seqOfSeqs:
        var first: seq[string] = sequence[0..3].reversed
        var second: seq[string] = sequence[4..5].reversed
        var third: seq[string] = sequence[6..7].reversed
        var fourth: seq[string] = sequence[8..9]
        var fifth: seq[string] = sequence[10..15]
        var uuid: string = first.join() & '-' & second.join() & '-' & third.join() & '-' & fourth.join() & '-' & fifth.join()
        uuids.add(uuid)
    return (len(uuids), uuids)

when isMainModule:
    if paramCount() == 0:
        quit("You must specify the path to the file containing raw shellcode as the only parameter.", -1)
    let sc_string = readFile(commandLineParams()[0]).toHex
    var uuids: seq[string]
    var uuidCount: int
    (uuidCount, uuids) = convertToUuid(sc_string)
    echo "Count: ", uuidCount
    echo $uuids
