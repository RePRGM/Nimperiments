import winim
import hash

template doWhile(a, b: untyped): untyped =
  b
  while a:
    b

template gmh*(s: string): HANDLE =
  getModuleHandleH(static(hashStrA(s.cstring)))

proc toLower(c: char): char {.inline.} =
  if c >= 'A' and c <= 'Z':
    return (c.int xor 0x20).char
  else: 
    return c

proc getModuleHandleH*(hash: uint32): HMODULE =
  var pPeb: PPEB

  asm """
    xor rax, rax
    mov rax, 0x10
    imul rax, rax, 6
    mov rax, qword ptr gs:[rax]
    :"=r"(`pPeb`)
  """

  let
    pLdr: PPEB_LDR_DATA = pPeb.Ldr
    pListHead: LIST_ENTRY = pPeb.Ldr.InMemoryOrderModuleList

  var
    pDte: PLDR_DATA_TABLE_ENTRY = cast[PLDR_DATA_TABLE_ENTRY](pLdr.InMemoryOrderModuleList.Flink)
    pListNode: PLIST_ENTRY = pListHead.Flink

  doWhile cast[int](pListNode) != cast[int](pListHead):
    if pDte.FullDllName.Length != 0:
      var 
        tmpStrA: array[MAX_PATH, CHAR]
        pStrW = cast[ptr UncheckedArray[int16]](pDte.FullDllName.Buffer)
        idx: int = 0
        isRunning = true

      while (isRunning):
        if pStrW[idx] == cast[int16]('.'):
          tmpStrA[idx] = 0.char
          isRunning = false

        if pStrW[idx] == 0:
          isRunning = false

        else:
          tmpStrA[idx] = toLower(pStrW[idx].CHAR)
          idx.inc

        if hash == hashStrA(cast[cstring](tmpStrA[0].addr)):
          return cast[HMODULE](pDte.Reserved2[0])
        
    pDte = cast[PLDR_DATA_TABLE_ENTRY](pListNode.Flink)
    pListNode = cast[PLIST_ENTRY](pListNode.Flink)
  return cast[HMODULE](0)