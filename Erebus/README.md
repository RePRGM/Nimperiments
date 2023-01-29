# Erebus
The Erebus project is a payload generator written in Nim. It is designed to automate the creation of stealthy, defensive-evasive Windows payloads in several formats including .exe, .dll, .xll, and .cpl.

Shellcode is stored in the .rsrc section of the resulting binaries encrypted with RC4, rather than AES, as this allows the shellcode to be decrypted in memory. Other evasive features include dynamic resolution of Kernel32 functions during runtime by locating them in Kernel32's EAT, unhooking functions, patching ETW, and anti-sandbox countermeasures. 
