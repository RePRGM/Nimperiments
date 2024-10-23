import 
  winim,
  gmh, 
  gpa, 
  stackstr
    
template PRINTA*(args: varargs[untyped]) =
  when defined(malDebug):
    var 
      hKernel32      = gmh("KERNEL32.DLL")
      pLoadLibraryA  = gpa(hKernel32, "LoadLibraryA", LoadLibraryA)
      sUser32 {.stackStringA.} = "user32.dll"
      hUser32        = pLoadLibraryA(CPTR(sUser32))
      pwsprintfA     = gpa(hUser32, "wsprintfA", wsprintfA)
      pLocalAlloc    = gpa(hKernel32, "LocalAlloc", LocalAlloc)
      pLocalFree     = gpa(hKernel32, "LocalFree", LocalFree)
      pGetStdHandle  = gpa(hKernel32, "GetStdHandle", GetStdHandle)
      pWriteConsoleA = gpa(hKernel32, "WriteConsoleA", WriteConsoleA)

    var buf = cast[LPSTR](pLocalAlloc(LPTR, 1024))
    if cast[uint](buf) != 0:
      var length = pwsprintfA(buf, args)
      discard pWriteConsoleA(pGetStdHandle(STD_OUTPUT_HANDLE), buf, length, NULL, NULL)
      discard pLocalFree(cast[HLOCAL](buf))

proc dumpHex*(data: pointer, size: int) {.inline.} =
  when defined(malDebug):
    var 
      p = cast[ptr byte](data)
      ascii: array[17, byte]
    for i in 0 ..< size:
      PRINTA("%02x ", p[])
      if p[] >= ' '.byte and p[] <= '~'.byte:
        ascii[i mod 16] = p[]
      else: ascii[i mod 16] = '.'.byte
      if ((i+1) mod 8) == 0 or (i + 1) == size:
        PRINTA(" ")
        if (i + 1) mod 16 == 0:
          PRINTA("|  %s \n", cast[cstring](ascii[0].addr))
        elif (i + 1) == size:
          ascii[(i+1) mod 16] = '\0'.byte
          if ((i+1) mod 16) <= 8:
            PRINTA(" ")
          for j in (i + 1) mod 16 ..< 16:
            PRINTA("   ")
          PRINTA("|  %s \n", cast[cstring](ascii[0].addr))
      p = cast[ptr byte](cast[uint](data) + i.uint + 1)
