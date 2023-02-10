# Nimperiments
A lot of random projects written in Nim.

# CreateThread
A very simple, basic project that does local process injection. No sandbox checks. No unhooking. No bypasses or patches. 

# Nimjection
A very simple, basic project that does remote process injection. No sandbox checks. No unhooking. No bypasses or patches.

# DLLoader
A very simple, basic project that does classic DLL injection. It _does_ have sandbox checking. It _does_ have ntdll unhooking (but no kernel32 unhooking). No other bypasses or patches. It downloads the DLL from a remote server onto disk. Could disable this functionality and use UNC paths as an alternative to avoid downloading to disk.

# Syscall_DLLoader
A slightly more advanced version of the "DLLoader" project that does classic DLL injection using syscalls. No sandbox checks. No unhooking. No other bypasses or patches. It downloads the DLL from a remote server onto disk. Could disable this functionality and use UNC paths as an alternative to avoid downloading to disk (untested).  
