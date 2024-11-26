import winim/lean
import instance

template PRINTA*(ninst: ptr NIMLESS_INSTANCE, args: varargs[untyped]) =
  when defined(malDebug):
    var 
      pwsprintfA = ninst.Win32.wsprintfA
      pLocalAlloc = ninst.Win32.LocalAlloc
      pLocalFree = ninst.Win32.LocalFree
      pGetStdHandle = ninst.Win32.GetStdHandle
      pWriteConsoleA = ninst.Win32.WriteConsoleA

    var buf = cast[LPSTR](pLocalAlloc(LPTR, 1024))
    if cast[uint](buf) != 0:
      var length = pwsprintfA(buf, args)
      discard pWriteConsoleA(pGetStdHandle(STD_OUTPUT_HANDLE), buf, length, NULL, NULL)
      discard pLocalFree(cast[HLOCAL](buf))