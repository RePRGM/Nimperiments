# Nimless
A template of sorts to build Offensive Security Tooling in Nim without the C Standard Library or the Nim Runtime. Features the bare minimum. *Should* compile as-is. Tested on Windows 10. *Should* be PIC as dependencies are manually resolved through custom `GetModuleHandle` and `GetProcAddress` functions and, by using stack strings, everything should be within the .text section. YMMV.

## Examples
The examples folder includes Work-in-Progress scripts to be used in combination with the utils folder, linker script ("script.ld") and Nim configuration file *unless noted otherwise*. It is a playground while I explore the capabilities and limitations of going without the Nim runtime and C standard libraries.

## Credit
Everything here is **heavily** based on (and/or often unmodified from) the [Writing Nimless](https://github.com/m4ul3r/writing_nimless/tree/main) repository. 
