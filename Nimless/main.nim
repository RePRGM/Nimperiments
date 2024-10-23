import winim

import utils/[gpa, gmh, hash, stdio, str]

proc main() {.exportc: "Main".} =
  var 
    hKernel32     = gmh("KERNEL32.DLL")
    pHeapAlloc    = gpa(hKernel32, "HeapAlloc", HeapAlloc)
    pGetProcessHeap = gpa(hKernel32, "GetProcessHeap", GetProcessHeap)
    pGetLastError = gpa(hKernel32, "GetLastError", GetLastError)

  PRINTA("[+] HeapAlloc: %p\n".cstring, cast[int](pHeapAlloc))
  PRINTA("[+] GetProcessHeap: %p\n".cstring, cast[int](pGetProcessHeap))

  var hProcHeap = pGetProcessHeap()
  PRINTA("[!] GetLastError after GetProcessHeap: %i\n".cstring, pGetLastError())

  var p = pHeapAlloc(pGetProcessHeap(), 0, 0x1000)
  PRINTA("[!] GetLastError after HeapAlloc: %i\n".cstring, pGetLastError())
  PRINTA("[+] Heap ptr: %p\n".cstring, cast[int](p))

  var test = "Test String Data\0".cstring
  copyMem(p, test[0].addr, strlenA(cast[int](test[0].addr)))
  PRINTA("[+] p contains: %s\n", p)

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