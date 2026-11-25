## DCE/RPC (connection-oriented) request PDU: encode and decode.
##
## The first 8 bytes of the common header are byte-order independent; the
## data representation label (drep) in bytes 4..7 then says how every later
## integer is encoded. NDR stub data is aligned relative to the stub start.

import std/syncio
import ../src/binstruct

const
  PtypeRequest = 0'u8
  PfcFirstFrag = 0x01'u8
  PfcLastFrag = 0x02'u8

template HeaderPrefix: untyped = "<BBBB4s"   # rpc_vers .. packed_drep
template HeaderRest: untyped = "=HHI"        # frag_length, auth_length, call_id
template RequestBody: untyped = "=IHH"       # alloc_hint, p_cont_id, opnum
template OpenArgs: untyped = "HIQ4s"         # NDR: flags, count, handle, tag

func drepFor(order: ByteOrder): array[4, byte] =
  ## Integer representation lives in the high nibble of byte 0.
  result = [(if order == boLittle: 0x10'u8 else: 0x00'u8), 0'u8, 0'u8, 0'u8]

func orderFromDrep(drep: array[4, byte]): ByteOrder =
  if (drep[0] shr 4) == 1'u8: boLittle else: boBig

proc encodeStub(order: ByteOrder; flags: uint16; count: uint32;
                handle: uint64; tag: string): seq[byte] =
  var w = initWriter(order)            # base 0 = the stub start
  writeFmt(w, OpenArgs, flags, count, handle, tag)
  result = w.data

proc encodeRequest(order: ByteOrder; callId: uint32; opnum: uint16;
                   stub: openArray[byte]): seq[byte] {.raises.} =
  var w = initWriter(order)
  writeFmt(w, HeaderPrefix, 5, 0, PtypeRequest, PfcFirstFrag or PfcLastFrag,
           drepFor(order))
  let fragLenPos = w.len
  writeFmt(w, HeaderRest, 0, 0, callId)          # frag_length patched below
  writeFmt(w, RequestBody, uint32(stub.len), 0, opnum)
  w.writeBytes(stub)
  patchFmt(w, "H", fragLenPos, uint16(w.len))
  result = w.data

proc decodeRequest(pdu: openArray[byte]) {.raises.} =
  var r = initReader(pdu)
  let (vers, minor, ptype, flags, drep) = readFmt(r, HeaderPrefix)
  if vers != 5'u8 or minor != 0'u8 or ptype != PtypeRequest: raise ProtocolError
  r.order = orderFromDrep(drep)                  # everything after obeys drep
  let (fragLen, authLen, callId) = readFmt(r, HeaderRest)
  if int(fragLen) != pdu.len: raise ProtocolError
  let (allocHint, ctxId, opnum) = readFmt(r, RequestBody)
  var stub = r.sub(int(fragLen) - r.pos)
  stub.base = stub.pos                           # NDR alignment restarts here
  let (sflags, count, handle, tag) = readFmt(stub, OpenArgs)
  echo "  order=", (if r.order == boLittle: "LE" else: "BE"),
       " flags=", flags, " frag_len=", fragLen, " auth_len=", authLen,
       " call_id=", callId, " alloc_hint=", allocHint, " ctx=", ctxId,
       " opnum=", opnum
  echo "  stub: flags=", sflags, " count=", count, " handle=", handle,
       " tag=", char(tag[0]), char(tag[1]), char(tag[2]), char(tag[3])

func hex(a: openArray[byte]): string =
  const d = "0123456789abcdef"
  result = ""
  for b in a:
    result.add d[int(b shr 4)]
    result.add d[int(b and 15)]

proc main() {.raises.} =
  for order in [boLittle, boBig]:
    let stub = encodeStub(order, 0x0102, 3, 0x1122334455667788'u64, "OPEN")
    let pdu = encodeRequest(order, 42, 7, stub)
    echo hex(pdu)
    decodeRequest(pdu)

try: main()
except ErrorCode as e: echo "error: ", $e
