# Evil Lsass Twin
Originally, a port of the [Dirty Vanity](https://github.com/deepinstinct/Dirty-Vanity) project to fork and dump the LSASS process. Has been updated upon further research to attempt to duplicate open handles to LSASS. If this fails, it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess. 

Nim, by default (or rather the Winim module) makes use of dynamic function resolution for Windows API functions, so the IAT should only include a reference to GetProcAddress and LoadLibrary (for better or worse).

The process cloning functionality has been updated to use make use of NtCreateProcessEx instead of RtlCreateProcessReflection as this only requires PROCESS_CREATE_PROCESS and does not create an initial thread (thereby triggering process creation kernel callbacks). 

Partial implementation of Process Ghosting technique is included to make use of the Delete On Close functionality. 

How this works: 
1. MiniDumpWriteDump function is used to dump forked LSASS process's memory into a file on-disk.
2. File is marked with Delete on Close and does not allow other threads to access it simultaneously.
3. File is mapped into memory
4. File is deleted after open handle to it is closed
5. Mapped Data (memory dump) is sent to server
 
Requires the `winim` and `ptr_math` modules. Several IOCs and opportunities for detection since this simple port was not originally built with stealth in mind. However, as noted above, this project _does_ include some stealthy features. 

Tested on Windows 10 22H2 and Windows 11 with Defender enabled (Cloud Analysis disabled).

Must be run from an Administrator Command Prompt or Powershell as EvilLsassTwin depends on the SeDebugPrivilege. 

_Note: SeDebugPrvilege is enabled by default on Elevated Powershell._

_Note: Tool will **not** work against PPL or Credential Guard. Tool also will not work when EDRs patch LSASS a la [Cortex XDR Modifications](https://www.paloaltonetworks.com/blog/security-operations/detecting-credential-stealing-with-cortex-xdr/)_

# Usage
This project was developed and tested with Nim 1.6.10 and 1.6.14. It is **not** compatible with Nim 2.0.

1. Install Dependencies with `nim dependencies` or through Nimble package manager (Atlas not yet tested)
2. Edit line 5  in `EvilLsassTwin.nim` file to include your server's (attacker machine) IP address. Optionally: You may change the port number on line 6 as well. If you do change the port, it needs to be changed within the `EvilTwinServer.nim` file as well.
3. Compile the project with `nim build`. _Note: this assumes EvilTwinServer will be run on a Linux machine. Manual compilation required otherwise_
4. `chmod +x EvilTwinServer && ./EvilTwinServer` Alternatively: `nc -lvnp 6500 > EvilTwin.dmp`
5. Transfer EvilLsassTwin.exe to (Windows) target machine and Run.   

# Resources
[Bill Demirkapi - Abusing Windows Implemention of Fork for Stealthy Memory Operations](https://billdemirkapi.me/abusing-windows-implementation-of-fork-for-stealthy-memory-operations/)

[Dirty Vanity](https://github.com/deepinstinct/Dirty-Vanity)

[TransactedSharpMiniDump](https://github.com/PorLaCola25/TransactedSharpMiniDump/tree/master)

[Rasta Mouse - Dumping LSASS with Duplicated Handles](https://rastamouse.me/dumping-lsass-with-duplicated-handles/)

[Rasta Mouse - Duplicating Handles in C#](https://rastamouse.me/duplicating-handles-in-csharp/)

[Splintercod3 - The Hidden Side of Seclogon - Part 2](https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-2.html)

[Diversenok - The Definitive Guide to Process Cloning on Windows](https://diversenok.github.io/2023/04/20/Process-Cloning.html)
