---
title: Anti-Debugging CTFs and integrity checker
description: A breakdown of basic anti-debugging techniques in two cool CTFs, and a taste of ScyllaHide exploration.
date: 2025-04-16
categories:
  - CTF
  - Anti-Debugging
media_subpath: /assets/posts/2025-16-04-anti-debugging-ctfs/
tags:
  - CTF
  - dev
pin: true
---

# 🧭 Introduction 

- Played through the [debugme CTF](https://app.hackthebox.com/challenges/72) on `HackTheBox`
    
- Tackled the [debugme CTF](https://github.com/guidedhacking/anti-debugging) by `GuidedHacking`
    
- Installed [ScyllaHide](https://github.com/x64dbg/ScyllaHide), did a quick review, and tested it on the latest challenges
    
- Wrote a basic **code integrity checker** 

## 🏴‍☠️ HTB debugme CTF

The `debugme` challenge is pretty chill. It performs some basic anti-debugging checks and decrypts its `main` function at runtime with a simple XOR loop.

Here's what we're dealing with:

- `PEB.BeingDebugged` check
    
- `PEB.NtGlobalFlag` check
    
- `RDTSC` timing-based anti-debugging
    
- Runtime XOR decryption of the `main` function
    
- XOR-encrypted hardcoded flag
    
- No ASLR (static base address FTW)


### 🔬 Analyze 

> Nothing fancy inside **TLS callbacks**, just the usual MinGW CRT init stuff. So we dive straight into the entry point: `mainCRTStartup_0`.
> {:.prompt-tip}

It starts by accessing the `PEB` and _checking_ the `BeingDebugged` field:

```nasm
_mainCRTStartup_0+7 : 
mov     eax, dword ptr fs:[00000030h]
mov     al, byte ptr [eax+2]
mov     dl, al
cmp     al, 0
```

Then it checks the `NtGlobalFlag`:

```nasm
_mainCRTStartup_0+18:
mov     eax, large fs:30h
mov     al, [eax+68h]
mov     dl, al
cmp     al, 0
jnz     short loc_1680
```

Which translates to:

```cpp
if ( NtCurrentPeb()->BeingDebugged )
    return printf("Looks like your doing something naughty. Stop it!!!");
  if ( LOBYTE(NtCurrentPeb()->NtGlobalFlag) )
    return printf("Looks like your doing something naughty. Stop it!!!");
```
> Attaching a debugger won't flip the `NtGlobalFlag`. But if the process is _created_ under a debugger, the following flags are set and stick around
> - `FLG_HEAP_ENABLE_TAIL_CHECK` (0x10) *Adds special patterns at the end of heap blocks to detect buffer overruns*
> - `FLG_HEAP_ENABLE_FREE_CHECK` (0x20) *Verifies memory patterns on freed blocks to catch double frees or use-after-free*
> - `FLG_HEAP_VALIDATE_PARAMETERS` (0x40) *Checks function arguments to heap APIs for correctness*
{:.prompt-info}

Next comes the `RDTSC` timing check:
```nasm
_mainCRTStartup_0+27:
rdtsc   ; old cpu cycles
mov     ebx, eax 
; waste time
rdtsc ; new cpu cycles
sub     eax, ebx
cmp     eax, 3E8h ; 
```

C equivalent:

```cpp
uint32_t t1 = __rdtsc();
__burn_cycles();
uint32_t t2 = __rdtsc();

if ((t2 - t1) > 0x3E8) {
    // Debugger detected!
    return;
}
```

> [`rdtsc`](https://fr.wikipedia.org/wiki/RDTSC) measures CPU cycles since reset. If you’re single-stepping, the gap is huge compared to normal execution classic anti-debugging trap.
> {:.prompt-info}

Then it decrypts the `sub_401620` function using a basic XOR loop:

```nasm
mov     eax, 401620h ; start of the function
xor     byte ptr [eax], 5Ch
inc     eax
cmp     eax, 401791h ; end of the function
jle     short loc_8973
```

C version:

```cpp
for ( i = 0x401620; i <= 0x401791; ++i )
          *(_BYTE *)i ^= 0x5C;
```

Let’s automate that with an IDA Python script:

```python
import ida_bytes

def xor_patch(start_ea, size, key):
    for i in range(size):
        ea = start_ea + i
        orig = ida_bytes.get_byte(ea)
        patched = orig ^ key
        ida_bytes.patch_byte(ea, patched)

    print(f"Patched {size} bytes from {hex(start_ea)} with XOR key {hex(key)}")


xor_patch(0x401620, 0x172, 0x5C) 
```

Alternatively, just dump the _function_ and analyze it later:

![dumping decrypted function using x32dbg](x32DbgDump.gif)
_dumping decrypted function using x32dbg_

The decrypted `sub_401620` is literally the **main** function:

![dumping decrypted function using x32dbg](sub_401620_decrypted.png)
_sub_401620 decrypted_

The challenge author repeats _all_ the same checks in the decrypted function, then it decrypts the flag: builds a 36-byte buffer using hardcoded DWORDs and XORs them with `0x4B`.

```nasm
mov     eax, 6A253E2Dh
push    eax
; bullshit
sub     eax, 560C29FCh
push    eax
; bullshit
and     eax, 41414141h
and     eax, 3E3E3E3Eh
mov     eax, 6A253E2Dh
sub     eax, 49FD1BF4h
push    eax
; ...
```

> Yeah, it’s a messy way of pushing encrypted data to the stack. It' simply statically resolved
> {:.category-info}

```cpp
  v10[8] = 0x6A253E2D;
  v10[7] = 0x14191431;
  v10[6] = 0x20282239;
  v10[5] = 0x3F14192E;
  v10[4] = 0xC0C3E29;
  v10[3] = 0x780F147A;
  v10[2] = 0x3F250A14;
  v10[1] = 0x2C252227;
  v10[0] = 0x277B391F;
```

> Reminder: IDA shows values in **big-endian**, but memory stores them **little-endian**, so the final byte stream looks like this:
{:.prompt-warning}


```cpp
	std::array<std::uint8_t, 36 > flag {
		0x1F, 0x39, 0x7B, 0x27,
		0x27, 0x22, 0x25, 0x2C,
		0x14, 0x0A, 0x25, 0x3F,
		0x7A, 0x14, 0x0F, 0x78,
		0x29, 0x3E, 0x0C, 0x0C,
		0x2E, 0x19, 0x14, 0x3F,
		0x39, 0x22, 0x28, 0x20,
		0x31, 0x14, 0x19, 0x14,
		0x2D, 0x3E, 0x25, 0x6A,
	};
```

Here’s the final XOR loop **that** decrypts the flag:

```nasm
loc_1788:
    lodsb
    xor     eax, ebx
    stosb
    loop    loc_1788
```

### 💻 Solution

This is the final c++ decryption code : 

```cpp
#include <array>
#include <cstdint>
#include <iostream>

template<std::size_t N>
consteval auto xorDecrypt( std::array<std::uint8_t, N> data, uint8_t key ) {
	for ( auto& b : data )
		b ^= key;
	return data;
}

int main( ) {
	constexpr std::uint8_t key { 0x4B };

	constexpr auto decrypted = xorDecrypt(
		std::array<std::uint8_t, 37>{
		0x1F, 0x39, 0x7B, 0x27,
			0x27, 0x22, 0x25, 0x2C,
			0x14, 0x0A, 0x25, 0x3F,
			0x7A, 0x14, 0x0F, 0x78,
			0x29, 0x3E, 0x0C, 0x0C,
			0x2E, 0x19, 0x14, 0x3F,
			0x39, 0x22, 0x28, 0x20,
			0x31, 0x14, 0x19, 0x14,
			0x2D, 0x3E, 0x25, 0x6A,
			0x4B // null terminator
	},
		key
	);

	std::cout << "[+] Flag: " << reinterpret_cast< const char* >( decrypted.data( ) ) << std::endl;
}
```


## 🏴‍☠️ GH debugme CTF

It's more interesting as it feature bigger arsenal of anti-debugging checks:

- `IsDebuggerPresent`
    
- `NtGlobalFlag`
    
- `PEB->BeingDebugged`
    
- `PEB->BeingDebugged` (_WoW64_)
    
- [`PROCESSENTRY32W`](https://learn.microsoft.com/fr-fr/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32w) (Parent PID check)
    
- [`CheckRemoteDebuggerPresent`](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-checkremotedebuggerpresent)
    
- [`UnhandledExceptionFilter`](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-unhandledexceptionfilter)
    
- [`ThreadHideFromDebugger`](https://github.com/ayoubfaouzi/al-khaser/blob/master/al-khaser/AntiDebug/NtSetInformationThread_ThreadHideFromDebugger.cpp)

We’ll start by reversing the _structure_ in IDA, then dig into each technique and how to bypass it.

### 🔬 Analyze

The application builds a basic GUI with a looped structure of callback checks. These callbacks are registered inside the `WndProc` and each performs a specific anti-debug trick.

Each callback is stored in a block with its flags, and the main loop iterate on each block; check if the block is enabled, runs it, and handles detection changes:

```cpp
do {
  bOldDetected = (*pCurrBlock)->bDetected; // old detection status

  if ((*pCurrBlock)->enabled && pCurrBlock->pCallback) {
    isDetected = pCurrBlock->pCallback(); // run callback
    pCurrBlock->bDetected = isDetected;

    if (bOldDetected != isDetected) { // new detected ? 
      detectionName = &pCurrBlock->debugStr.strBuffer;
      if (pCurrBlock->debugStr.capacity >= 0x10u)
        detectionName = *&pCurrBlock->debugStr.strBuffer;

      strcpy_s(Destination, 0xC8u, detectionName);
      strcat_s(Destination, 0xC8u, "
 ENABLED - DETECTED!");
      ::SendMessageA(pCurrBlock->hWndDebug, 0xCu, 0, Destination);
      isDetected = pCurrBlock->bDetected;
    }

    if (isDetected && !g_detected_406419) { // globally detected ?
      g_detected_406419 = 1;
      std::cout_402530(std::cout, "detected!");
      std::cout_402530(sub_2780(pCurrBlock->debugStr.len, v13), "
");
    }
  } else {
    pCurrBlock->bDetected = 0;
  }
  ++pCurrBlock;
} while (pCurrBlock < g_pBlockEnd_406424);
```

Callbacks are registered like this:

```cpp
createGUI_402030(IsDebuggerPresent, "IsDebuggerPresent()");
createGUI_402030(BeingDebugged, "PEB->BeingDebugged");
createGUI_402030(NtGlobalFlag, "NtGlobalFlag");
createGUI_402030(CheckRemoteDebuggerPresent, "CheckRemoteDebuggerPresent()");
createGUI_402030(CheckParentProcess, "Check Parent Process (CreateToolhelp32Snapshot)");
createGUI_402030(UnhandledExceptionFilter, "UnhandledExceptionFilter");
createGUI_402030(WoW64_BeingDebugged, "WoW64 PEB->BeingDebugged");
createGUI_402030(ThreadHideFromDebugger, "ThreadHideFromDebugger (will crash if debugged)");
```

Time to dissect each check.

### 🛡️ Anti-Debugging checks

#### PEB debug flags

Both `IsDebuggerPresent` and `BeingDebugged` just check the `PEB->BeingDebugged` field:
```nasm
mov     rax, gs:60h
movzx   eax, byte ptr [rax+2]
retn
```

The `NtGlobalFlag` check is just as straightforward:

```cpp
mov     rax, gs:60h
mov   eax, dword ptr [rax+68h]
retn
```

The WoW64 variant uses a transition stub aka “**Heaven’s Gate**” to switch to 64-bit mode and access the 64-bit PEB:

```
00047000: push    33h ; Push segment selector 0x33 → this is the 64-bit code segment
00047002: call   $+5;  get next instruction address on the stack  (00007007)
00047007: add     [esp], 5; add 5 to the address (00047007 + 5)
0004700B: retf; 0x33:0004700C ( switches execution to 64-bit mode )
```

> This switches execution to **x64 mode**. To analyze it in IDA, resize the segment and create a new 64-bit segment starting at `0x0004700C`.
{:.prompt-info}
> 

![ida segment](segment.png)
_ida segment layout_

```
4700C: mov     rax, large gs:60h ; gs:[0x60] is the PEB in 64-bit context.
47014: movzx   rax, byte ptr [rax+2] ; read PEB->BeingDebugged
47019: call    $+5
4701E: mov     dword ptr [rsp+4], 23h ; '#' ; back to 32-bit code segment (0x23)
47026: add     dword ptr [rsp], 0Dh ; 40701E + D
4702A: retf                    ; do return to 0x23:40702B
4702B: retn                    ; execute this instruction in 32bit, return to caller with eax = beingDebugged 
```

Simply overwrite the `BeingDebugged` and `NtGlobalFlag`, same for WoW64 use x64 transition stub to write into 64-bit PEB memory. 

---
#### CheckParentProcess


This one enumerates **processes** and finds the parent PID. If the parent is a known debugger, you're flagged. It use `CreateToolhelp32Snapshot` and `K32GetModuleBaseNameA`


```cpp
Toolhelp32Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
CurrentProcessId = GetCurrentProcessId();

if (Process32FirstW(Toolhelp32Snapshot, &pe)) {
  while (pe.th32ProcessID != CurrentProcessId && Process32NextW(Toolhelp32Snapshot, &pe));
}

hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pe.th32ParentProcessID);

if (hProcess) {
  K32GetModuleBaseNameA(hProcess, 0, parentModuleName, 0x63u);
  CloseHandle(hProcess);
}
  // compare parentModuleName with a list of debuggers name
```

We can hook `Process32NextW`, `K32GetModuleBaseNameA` ... or patch the whole thing out.

---
#### CheckRemoteDebuggerPresent

This one calls `NtQueryInformationProcess` with `ProcessDebugPort (8)`:

```cpp
NtQueryInformationProcess(hProcess, ProcessDebugPort, &ProcessInformation, 8u, 0);
*pbDebuggerPresent = ProcessInformation != 0;
```

Just hook `NtQueryInformationProcess` or `CheckRemoteDebuggerPresent`...

---
#### UnhandledExceptionFilter


Classic `SEH` trap. It installs a top-level exception filter, sets a flag, and triggers an `EXCEPTION_BREAKPOINT`. If a debugger is present, the exception is caught and the filter isn’t triggered.

```nasm
push offset TopLevelExceptionFilter ; address of the routine to exexute if the execption is unhandled
mov     g_debuger_40601C, 1 ; we assume a debugger is present
call    ds:SetUnhandledExceptionFilter
int 3; 
mov     al, g_debuger_40601C; return the result
retn
```

The filter itself clears the flag **and** skips the `int 3` on return:

```nasm
mov     eax, [ebp+ExceptionInfo] ; _EXCEPTION_POINTERS
mov     g_debuger_40601C, 0 ; no debugger is present since it's not handled
mov     eax, [eax+4] ; _EXCEPTION_POINTERS->PCONTEXT
inc     dword ptr [eax+0B8h] ; ++ExceptionInfo->ContextRecord->Eip ; skip int 3
```

In this case simply patch `int 3` and  initialize the debugger flag to 0 directly.

---
#### ThreadHideFromDebugger

The `ThreadHideFromDebugger` use [`NtSetInformationThread`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/nf-ntifs-ntsetinformationthread) to set the flag `ThreadHideFromDebugger`. 

```nasm
cmp     threadHidden_406418, 0
mov     NtQueryInformationThread_406410, eax
jnz     short already_hidden_19D3
push    0
push    0
push    11h ; ThreadHideFromDebugger
push    ebx
call    NtSetInformationThread
```

The `ThreadHideFromDebugger` queries or enables suppression of debug events generated on the thread. Threads that do not generate debug events are essentially invisible to debuggers.  Any **breakpoints** or **exceptions** that are triggered will cause the process to crash. Due to the fact that the debugger cannot see this


You can hook [`NtSetInformationThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationthread) to disable the call. You could also try manipulating the `ETHREAD` structure to un-hide threads if you are in kernel-space. 

### 💻 C++ bypass 

This is an **overview** of the bypass, you can find the full code on my [github](https://github.com/R-X-V/R-X-V-Collections/tree/main/ctf/win_debugme_gh) : 

```cpp
DWORD WINAPI EntryPoint( LPVOID hModule ) {

	PortableExecutable antiDebug;
	WindowsDynamicLibrary kernelbase { "kernelbase.dll" };
	WindowsDynamicLibrary kernel32 { "kernel32.dll" };
	WindowsDynamicLibrary ntdll { "ntdll.dll" };

	auto& bypass = BypassGH::GetBypass( );

	/* Initialize Refererences */
	Patch<1>& sehForceNoDbg = sehBypass::forceNoDbg::patch;
	Patch<1>& sehForceNoBrkp = sehBypass::forceNoBrkp::patch;
	Hook& checkRemoteDebuggerPresentHk = checkRemoteDebuggerPresentBypass::hook;
	Hook& checkParentProcessHk = checkParentProcessBypass::hook;
	Hook& hiddenThreadHk = hiddenThreadBypass::hook;


	/* Search memory addresses */
	auto sehForceNoDbgAddr = antiDebug.searchInCodeSection( sehBypass::forceNoDbg::pattern ) + sehBypass::forceNoDbg::offset;
	auto sehForceNoBrkpAddr = antiDebug.searchInCodeSection( sehBypass::forceNoBrkp::pattern ) + sehBypass::forceNoBrkp::offset;
	auto checkRemoteDebuggerPresentAddr = kernelbase.getFunctionAddress( checkRemoteDebuggerPresentBypass::fnName );
	auto process32NextAddr = kernel32.getFunctionAddress( checkParentProcessBypass::fnName );
	auto ntSetInfoThreadAddr = ntdll.getFunctionAddress( hiddenThreadBypass::fnName );

	/* Initalize Patches */
	sehForceNoDbg.initialize( sehForceNoDbgAddr, sehBypass::forceNoDbg::bytes );
	sehForceNoBrkp.initialize( sehForceNoBrkpAddr, sehBypass::forceNoBrkp::bytes );

	/* Initalize Hooks */
	checkRemoteDebuggerPresentHk.registerTarget(
		checkRemoteDebuggerPresentAddr,
		checkRemoteDebuggerPresentBypass::detour,
		checkRemoteDebuggerPresentBypass::len
	);

	checkParentProcessHk.registerTarget(
		process32NextAddr,
		checkParentProcessBypass::detour,
		checkParentProcessBypass::len
	);

	hiddenThreadHk.registerTarget(
		ntSetInfoThreadAddr,
		hiddenThreadBypass::detour,
		hiddenThreadBypass::len
	);

	/* Add Patches */
	bypass.addPatch( std::ref( sehForceNoDbg ) );
	bypass.addPatch( std::ref( sehForceNoBrkp ) );

	/* Add Hooks */
	bypass.addHook( std::ref( checkRemoteDebuggerPresentHk ) );
	bypass.addHook( std::ref( checkParentProcessHk ) );
	bypass.addHook( std::ref( hiddenThreadHk ) );

	bypass.applyAll( );
	antiDebug.deleteDebugFlags( );
	antiDebug.deleteWow64DebugFlags( );
	
	return 0;
}
```
## 🕵️‍♂️ Scyllahide 

[ScyllaHide](https://github.com/x64dbg/ScyllaHide) is an advanced open-source x64/x86 user-mode Anti-Anti-Debug library. It hooks various system APIs to mask debugger presence.

It has a ton of features, and nearly all of them are built around [hooking](https://github.com/x64dbg/ScyllaHide/blob/master/HookLibrary/HookedFunctions.h) key API calls. It injects a module that actively patches memory and function behavior to fool debugger detection logic.

Depending on the options you enable, it’ll hook a bunch of `Nt*` functions:

![overview](scyllahide.png){: w="400" h="400" }

For instance, let’s write a small snippet calling `CheckRemoteDebuggerPresent`:

```cpp
auto success = CheckRemoteDebuggerPresent( GetCurrentProcess( ), &present );
```

If you enable the `NtQueryInformationProcess` protection in ScyllaHide, the debugger won’t get detected. Why? Because  `ntdll.NtQueryProcessInformation` is hooked : 

![overview](modifiedbytes.png){: w="600" h="600" }

When following the hook, it still ends up calling the original `NtQueryInformationProcess`

```nasm
mov     eax, 19h
syscall
```

but afterward, it return to the hook logic, and **overrides** the result:

```nasm
hook:
and qword ptr ds:[rdi], 0x0 ; rdi contain the result of NtQueryInformationProcess
jmp end;
```

To defeat these sneaky hooks, we apply **integrity checking**. The idea: load a clean copy of a DLL (like `ntdll.dll`) and compare it to the one in memory that might’ve been hooked.

To load a clean copy of an image you can do it by accessing global memory-mapped shared `_SECTION` object managed by the Object Manager, load the image from disk manually,  even pull it securely from a remote server. 

These techniques let you bypass user-mode tampering and give you a clean baseline for diffing against what’s actually running in memory and compare it to the one in memory that might’ve been hooked.

In real-world scenarios, these integrity checks are often heavily obfuscated, randomized between releases, or even dynamically delivered and virtualized by a server—making them a nightmare to locate statically. Patching the integrity routine itself is risky and usually harder than finding the clean image in memory and targeting that instead. And patching the file on disk? Often pointless. Many modern apps, especially anti-cheats or protected launchers, verify file hashes with a server before even starting up

This basic PoC is sufficient to defeat ScyllaHide in practice, as it detects tampering on critical functions like `NtQueryInformationProcess` It use `NtOpenSection` or `NtCreateSection` to load a clean shared memory section. From there, the integrity checker uses structured PE parsing, / section-by-section comparison /  unwind data from `.pdata` to validate the memory layout.

Here’s a minimal PoC of a **loader** + checker, you can find it in [github](https://github.com/R-X-V/R-X-V-Collections/tree/main/dev/poc_integrity_checker)

```cpp
int main() {
    Loader loader;
    IntegrityChecker checker;
    WindowsModule ntdll { "ntdll.dll" }; // Untrusted

    // Load trusted copy
    if (!loader.loadImageFromMemory<HASH("ntdll.dll")>())
        return 0;

    WindowsModule trustedNtdll { loader.baseAddress };
    auto trustedFunc = trustedNtdll.getPortableExecutable().getExport("NtQueryInformationProcess").getRawAddress();

    if (!trustedFunc)
        return 0;

    while (!(GetAsyncKeyState(VK_END) & 1)) {
        // Check integrity of NtQueryInformationProcess
        bool integrity = checker.checkFunction(ntdll, trustedNtdll, trustedFunc);

        BOOL present {};
        auto success = CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);

        if (!success || present || !integrity) {
            std::cout << "debugger detected!" << std::endl;
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    return 0;
}
```

As you can see, once we attach a debugger to a challenge using this integrity checker, ScyllaHide gets bypassed—because we detect its patch.


![integrity check](scyllahide_detected.gif)


## 🔗 Further Reading

- [debugme HTB](https://app.hackthebox.com/challenges/72) 
- [debugme GH](https://github.com/guidedhacking/anti-debugging)
- [ScyllaHide](https://github.com/x64dbg/ScyllaHide)
- [wow64 stuff](https://medium.com/@fsx30/hooking-heavens-gate-a-wow64-hooking-technique-5235e1aeed73)
- [Anti-Debugging Stuff](https://guidedhacking.com/threads/anti-debug-techniques-a-comprehensive-guide.20391/)
- [Anti-Debugging: Timing](https://anti-debug.checkpoint.com/techniques/timing.html)
- [SEH](https://blog.elmo.sg/posts/structured-exception-handler-x64/)
- [Integrity check EAC](https://secret.club/2020/04/08/eac_integrity_check_bypass.html)
- [Osiris *(modern generic programming style)*](https://github.com/danielkrupinski/Osiris)

## 💭 Reflections 

This being my first blog post, I made a conscious choice to keep the explanations tight and focused. I’m not aiming to write a full-blown technical manual on Windows internals or reverse engineering concepts in each article. Instead, I want to go straight to the point—walk through interesting findings, demonstrate practical techniques, and leave some space for readers to explore the details on their own.

If you're reading this and curious about something I skipped or mentioned briefly, consider it an invitation to dive in and research deeper. I’ll try to keep the same style for future posts.

## 🚀 Conclusion 

Modern CTFs love throwing anti-debug tricks your way, and tools like ScyllaHide are a huge help. This kind of integrity checker adds a trusted baseline to catch tampering in real time, and you can build crazy advanced stuff on top of it.

In the next article, we’ll dive into way more advanced stuff, **next post** : "a stealthy loader that injects an encrypted DLL into Firefox's address space, decrypts it in memory, and manually maps it. This setup also explores good malware development practices to reduce detection rates for both the module and the loader itself. "

It will be followed by experiments in virtualized CTFs, a C++20 modern injector, VAC reversing, and even some reversing  playgrounds.












