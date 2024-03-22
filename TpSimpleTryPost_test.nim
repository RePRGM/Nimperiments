when defined(windows):
  import winim

const
  ALLOC_ON_CODE: untyped = ""

var
  CallbackStub: array[5, uint8] = [0x48'u8, 0x89'u8, 0xd3'u8,            # mov rbx, rdx
                                   0x48'u8, 0x8b'u8, 0x03'u8,            # mov rax, QWORD PTR[rbx]
                                   0x48'u8, 0x8b'u8, 0x4b'u8, 0x08'u8,  # mov rcx, QWORD PTR[rbx + 0x8]
                                   0xff'u8, 0xe0'u8]                   # jmp rax

type
  LOADLIBRARY_ARGS = object
    pLoadLibraryA: UINT_PTR
    lpLibFileName: LPCSTR

proc main() =
  var loadLibraryArgs: LOADLIBRARY_ARGS
  loadLibraryArgs.pLoadLibraryA = cast[UINT_PTR](GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"))
  loadLibraryArgs.lpLibFileName = "user32.dll"

  # Code to call TrySubmitThreadpoolCallback and other API calls
  let TrySubmitThreadpoolCallback = winim.TrySubmitThreadpoolCallback
  let PTP_SIMPLE_CALLBACK = winim.PTP_SIMPLE_CALLBACK
  let callback = cast[PTP_SIMPLE_CALLBACK](CallbackStub.addr)

  TrySubmitThreadpoolCallback(callback, addr loadLibraryArgs, 0)

  # Print user32.dll address
  printf("user32.dll Address: %p\n", cast[pointer](GetModuleHandleA("user32.dll")))

when defined(windows):
  main()
