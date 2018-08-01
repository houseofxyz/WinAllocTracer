## WinMallocTracer

[Pin-based tool](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool)

Potential uses of this `Pintool` include, but are not limited to:
* Log all memory (de)allocations (`RtlAllocateHeap`, `RtlReAllocateHeap`, `RtlFreeHeap`, `VirtualAllocEx`, and `VirtualFreeEx`)
* Detect `invalid allocations`
* Detect `double frees`
* Detect `memory leaks`
* Detect `use after frees`

### Status

* This is work in progress
* Proof of concept code, tested in a small number of situations

### Building

* Built with Visual Studio 2015/2017


### Using the Pintool

```
C:\pin>pin -t source\tools\WinMallocTracer\Release\WinMallocTracer.dll -- C:\TARGET\testcase.exe
[+] Loading C:\TARGET\testcase.exe, Image id = 1
    Low Adress : 1638400, High Address : 1765375
[+] Loading C:\Windows\syswow64\KERNELBASE.dll, Image id = 2
    Low Adress : 1979580416, High Address : 1979871231
[+] Loading C:\Windows\syswow64\kernel32.dll, Image id = 3
    Low Adress : 1984888832, High Address : 1986002943
[+] Loading C:\Windows\SysWOW64\ntdll.dll, Image id = 4
    Low Adress : 2005532672, High Address : 2007105535
[+] Loading C:\Windows\SysWOW64\vcruntime140d.dll, Image id = 5
    Low Adress : 1854865408, High Address : 1854971903
[+] Loading C:\Windows\SysWOW64\ucrtbased.dll, Image id = 6
    Low Adress : 1720320000, High Address : 1721843711
[+] Loading C:\Windows\SysWOW64\api-ms-win-core-localization-l1-2-0.dll, Image id = 7
    Low Adress : 1884225536, High Address : 1884237823
[+] Loading C:\Windows\SysWOW64\api-ms-win-core-processthreads-l1-1-1.dll, Image id = 8
    Low Adress : 1879834624, High Address : 1879846911
[+] Loading C:\Windows\SysWOW64\api-ms-win-core-file-l1-2-0.dll, Image id = 9
    Low Adress : 1879769088, High Address : 1879781375
[+] Loading C:\Windows\SysWOW64\api-ms-win-core-timezone-l1-1-0.dll, Image id = 10
    Low Adress : 1884356608, High Address : 1884368895
[+] Loading C:\Windows\SysWOW64\api-ms-win-core-file-l2-1-0.dll, Image id = 11
    Low Adress : 1884291072, High Address : 1884303359
[+] Loading C:\Windows\SysWOW64\api-ms-win-core-synch-l1-2-0.dll, Image id = 12
    Low Adress : 1879900160, High Address : 1879912447
Unloading imageC:\TARGET\testcase.exe
Unloading imageC:\Windows\syswow64\KERNELBASE.dll
Unloading imageC:\Windows\syswow64\kernel32.dll
Unloading imageC:\Windows\SysWOW64\ntdll.dll
Unloading imageC:\Windows\SysWOW64\vcruntime140d.dll
Unloading imageC:\Windows\SysWOW64\ucrtbased.dll
Unloading imageC:\Windows\SysWOW64\api-ms-win-core-localization-l1-2-0.dll
Unloading imageC:\Windows\SysWOW64\api-ms-win-core-processthreads-l1-1-1.dll
Unloading imageC:\Windows\SysWOW64\api-ms-win-core-file-l1-2-0.dll
Unloading imageC:\Windows\SysWOW64\api-ms-win-core-timezone-l1-1-0.dll
Unloading imageC:\Windows\SysWOW64\api-ms-win-core-file-l2-1-0.dll
Unloading imageC:\Windows\SysWOW64\api-ms-win-core-synch-l1-2-0.dll

C:\pin>type memprofile.out
[+] Memory tracing for PID = 4532

 Image Name          : C:\TARGET\testcase.exe
 Image Load offset   : 0x1638400
 Image Low address   : 0x1638400
 Image High address  : 0x1765375
 Image Start address : 0x1638400
 Image Size mapped   : 126976
 Image Type          : 2

[+] Started tracing after 'main()' call

[*] RtlAllocateHeap(0x005b0000, 8, 32)    = 0x5cc628
[*] RtlFreeHeap(0x005b0000, 0, 0x5cc628)
[Use After Free] Chunk: 0x5cc632  Instruction: 0x1a1a55 mov al, byte ptr [edx+ecx*1]
[Use After Free] Chunk: 0x5cc63c  Instruction: 0x1a1a69 mov byte ptr [edx+ecx*1], al
[*] RtlAllocateHeap(0x005b0000, 8, 64)    = 0x5cea78
[*] RtlAllocateHeap(0x005b0000, 8, 128)   = 0x5cdd30
[*] RtlAllocateHeap(0x005b0000, 8, 256)   = 0x5cddb8
[*] RtlFreeHeap(0x005b0000, 0, 0x5cdd30)
[*] RtlAllocateHeap(0x005b0000, 8, 512)   = 0x5cdec0
[*] RtlFreeHeap(0x5cdec0) called from RtlHeapRealloc()
[*] RtlHeapReAlloc(0x005b0000, 8, 0x5cdec0, 1024)   = 0x5cdec0
[*] RtlFreeHeap(0x005b0000, 0, 0x5cdec0)
[*] VirtualAllocEx(0xffffffff, 0, 327680, 8192, 1)    = 0x2720000
[*] VirtualFreeEx(0xffffffff, 0x2720000, 0, 8000)
[Double Free] Memory at address 0x2720000 has been freed more than once (Caller IP: 0x75fef07f)
[Memory Leak] Memory at address 0x5cea78 has been allocated but not freed
[Memory Leak] Memory at address 0x5cddb8 has been allocated but not freed
```

### Acknowledgment

* This code is based on the sample `Pin` tools distributed as part of the `Pin` package.
* Started as a PoC for [http://deniable.org/reversing/binary-instrumentation](http://deniable.org/reversing/binary-instrumentation).

Also, lots of inspiration from:
* http://github.com/joxeankoret/membugtool
* https://github.com/JonathanSalwan/PinTools

