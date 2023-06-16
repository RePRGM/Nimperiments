# Nimperiments
A lot of random projects written in Nim.

## CreateThread
A very simple, basic project that does local process injection. No sandbox checks. No unhooking. No bypasses or patches. 

## Nimjection
A very simple, basic project that does remote process injection. No sandbox checks. No unhooking. No bypasses or patches.

## DLLoader
A very simple, basic project that does classic DLL injection. It _does_ have sandbox checking. It _does_ have ntdll unhooking (but no kernel32 unhooking). No other bypasses or patches. It downloads the DLL from a remote server onto disk. Could disable this functionality and use UNC paths as an alternative to avoid downloading to disk.

## Syscall_DLLoader
A slightly more advanced version of the "DLLoader" project that does classic DLL injection using syscalls. No sandbox checks. No unhooking. No other bypasses or patches. It downloads the DLL from a remote server onto disk. Could disable this functionality and use UNC paths as an alternative to avoid downloading to disk (untested). Depends on NimGetSysallStub project.

## UUID
Takes a raw shellcode file as an argument and encodes it into UUID strings. That's it. Not my code. Just glued together.

## DJB2
Takes whatever string you want to hash as an argument and hashes it using a slightly modified version of DJB2. You can thank ChatGPT for this one. Spat out bad code, but close enough that even I could fix it. 

## Perun's Fart
A port of the Perun's Fart NTDLL Unhooking (aka unhooking from suspended process) technique to Nim. Ported from @D1rkMtr's github, mixed in and glued together with code from  [@S3cur3Th1sSh1t's Nim DInvoke](https://github.com/S3cur3Th1sSh1t/Nim_DInvoke).

## Evil Lsass Twin
A port of the [Dirty Vanity](https://github.com/deepinstinct/Dirty-Vanity) project to fork and dump the lsass process. Requires the `winim` module. (Cross-)Compile with `nim c -d:mingw --cpu:amd64 --app=console -o=evillsasstwin.exe evillsasstwin.nim`
