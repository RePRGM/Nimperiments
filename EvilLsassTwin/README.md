# Evil Lsass Twin
Originally, a port of the [Dirty Vanity](https://github.com/deepinstinct/Dirty-Vanity) project to fork and dump the LSASS process. Has been updated upon further research to attempt to duplicate open handles to LSASS. If this fails, it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess. 

Nim, by default (or rather the Winim module) makes use of dynamic function resolution for Windows API functions, so the IAT should only include a reference to GetProcAddress and LoadLibrary (for better or worse).

The process cloning functionality has been updated to use make use of NtCreateProcessEx instead of RtlCreateProcessReflection as this only requires PROCESS_CREATE_PROCESS. 

Partial implementation of Process Ghosting technique is included to make use of the Delete On Close functionality. 

How this works: 
1. MiniDumpWriteDump function is used to dump forked LSASS process's memory into a file on-disk.
2. File is marked with Delete on Close and does not allow other threads to access it simultaneously.
3. File is mapped into memory
4. File is deleted after open handle to it is closed
5. Mapped Data (memory dump) is sent to server
 
Requires the `winim` and `ptr_math` modules. Numerous IOCs and opportunities for detection since this simple port was not built with stealth in mind. However, as noted above, this project _does_ include some stealthy features. Tested on Windows 10 22H2 and Windows 11 with Defender enabled (Cloud Analysis disabled).

# Usage
This project was developed and tested with Nim 1.6.14. It has not yet been tested for compatibility with Nim 2.0.

1. Install Dependencies with `nim dependencies` or through Nimble package manager (Atlas not yet tested)
2. Edit line 459 in `EvilLsassTwin.nim` file to include your server's (attacker machine) IP address. Optionally: You may change the port number as well.
3. Compile the project with `nim build`.
4. `chmod +x EvilLsassTwinServer && ./EvilLsassTwinServer`
5. Transfer EvilLsassTwin.exe to (Windows) target machine and Run.   
