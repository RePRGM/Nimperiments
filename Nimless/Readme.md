# Nimless
A template of sorts to build Offensive Security Tooling in Nim without the C Standard Library or the Nim Runtime. Features the bare minimum. *Should* compile as-is. Tested on Windows 10. *Should* be PIC as dependencies are manually resolved through custom `GetModuleHandle` and `GetProcAddress` functions and everything should be within the .text section. YMMV.
