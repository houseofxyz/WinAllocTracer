#include "pin.h"

namespace WINDOWS
{
#include <windows.h>
}

#include <iostream>
#include <fstream>
#include <map>

using namespace std;

map<ADDRINT, bool> MallocMap;
ofstream LogFile;
KNOB<string> LogFileName(KNOB_MODE_WRITEONCE, "pintool", "o", "memprofile.out", "Memory trace file name");
KNOB<string> EntryPoint(KNOB_MODE_WRITEONCE, "pintool", "entrypoint", "main", "Guest entry-point function");
KNOB<BOOL> EnumSymbols(KNOB_MODE_WRITEONCE, "pintool", "symbols", "0", "List Symbols");
BOOL start_trace = false;

VOID LogBeforeVirtualAlloc(WINDOWS::HANDLE hProcess, ADDRINT lpAddress, WINDOWS::SIZE_T dwSize, WINDOWS::DWORD flAllocationType, WINDOWS::DWORD flProtect, ADDRINT ret)
{
  if (!start_trace)
    return;

  LogFile << "[*] VirtualAllocEx(" << hex << hProcess << ", " << hex << lpAddress << ", " << dec << dwSize << ", " << dec << flAllocationType << ", " << dec << flProtect <<")";
}

VOID LogAfterVirtualAlloc(ADDRINT addr, ADDRINT ret)
{
  if (!start_trace)
    return;

  if (addr == NULL)
  {
    cerr << "[-] Error: VirtualAllocEx() return value was NULL.";
    return;
  }

  map<ADDRINT, bool>::iterator it = MallocMap.find(addr);

  if (it != MallocMap.end())
  {
    if (it->second)
      it->second = false;
    else
      cerr << "[-] Error: allocating memory not freed!?!" << endl;
  }
  else
  {
    MallocMap.insert(pair<ADDRINT, bool>(addr, false));
    LogFile << "\t\t= 0x" << hex << addr << endl;
  }
}

VOID LogBeforeVirtualFree(WINDOWS::HANDLE hProcess, ADDRINT lpAddress, WINDOWS::SIZE_T dwSize, WINDOWS::DWORD dwFreeType, ADDRINT ret)
{
  if (!start_trace)
    return;

  map<ADDRINT, bool>::iterator it = MallocMap.find(lpAddress);

  if (it != MallocMap.end())
  {
    if (it->second)
      LogFile << "[*] Memory at address 0x" << hex << lpAddress << " has been freed more than once (double free)." << endl;
    else
    {
      it->second = true;    // Mark it as freed
      LogFile << "[*] VirtualFreeEx(0x" << hex << hProcess << ", " << hex << lpAddress << ", " << dwSize << ", " << dwFreeType << ")" << endl;
    }
  }
  else
    LogFile << "[*] Freeing unallocated memory at address 0x" << hex << lpAddress << " (invalid free)." << endl;
}

VOID LogBeforeReAlloc(WINDOWS::HANDLE hHeap, WINDOWS::DWORD dwFlags, ADDRINT freed_addr, WINDOWS::DWORD dwBytes, ADDRINT ret)
{
  if (!start_trace)
    return;

  // mark freed_addr as free
  map<ADDRINT, bool>::iterator it = MallocMap.find(freed_addr);

  if (it != MallocMap.end())
  {
    it->second = true;
    LogFile << "[*] RtlFreeHeap(0x" << hex << freed_addr << ") from RtlHeapRealloc()" << endl;
  }
  else
    LogFile << "[-] RtlHeapRealloc could not find addr to free??? - " << freed_addr << endl;

  LogFile << "[*] RtlHeapReAlloc(" << hex << hHeap << ", " << dwFlags << ", 0x" << hex << freed_addr << ", " << dec << dwBytes << ")";
}

VOID LogAfterReAlloc(ADDRINT addr, ADDRINT ret)
{
  if (!start_trace)
    return;

  if (addr == NULL)
    return;

  map<ADDRINT, bool>::iterator it = MallocMap.find(addr);

  if (it != MallocMap.end())
  {
    if (it->second)
      it->second = false;
    else
      // it already exists because of the HeapAlloc, we don't need to insert... just log it
      LogFile << "\t\t= 0x" << hex << addr << endl;
  }
}

VOID LogBeforeMalloc(WINDOWS::HANDLE hHeap, WINDOWS::DWORD dwFlags, WINDOWS::DWORD dwBytes, ADDRINT ret)
{
  if (!start_trace)
    return;

  LogFile << "[*] RtlAllocateHeap(" << hex << hHeap << ", " << dwFlags << ", " << dec << dwBytes << ")";
}

VOID LogAfterMalloc(ADDRINT addr, ADDRINT ret)
{
  if (!start_trace)
    return;

  if (addr == NULL)
  {
    cerr << "[-] Error: RtlAllocateHeap() return value was NULL.";
    return;
  }

  map<ADDRINT, bool>::iterator it = MallocMap.find(addr);

  if (it != MallocMap.end())
  {
    if (it->second)
      it->second = false;
    else
      cerr << "[-] Error: allocating memory not freed!?!" << endl;
  }
  else
  {
    MallocMap.insert(pair<ADDRINT, bool>(addr, false));
    LogFile << "\t\t= 0x" << hex << addr << endl;
  }
}

VOID LogFree(WINDOWS::HANDLE hHeap, WINDOWS::DWORD dwFlags, ADDRINT BaseAddress, ADDRINT ret)
{
  if (!start_trace)
    return;

  map<ADDRINT, bool>::iterator it = MallocMap.find(BaseAddress);

  if (it != MallocMap.end())
  {
    if (it->second)
      LogFile << "[*] Memory at address 0x" << hex << BaseAddress << " has been freed more than once (double free)." << endl;
    else
    {
      it->second = true;    // Mark it as freed
      LogFile << "[*] RtlFreeHeap(" << hex << hHeap << ", " << dwFlags << ", 0x" << hex << BaseAddress << ")" << endl;
    }
  }
  else
    LogFile << "[*] Freeing unallocated memory at address 0x" << hex << BaseAddress << " (invalid free)." << endl;
}

VOID BeforeMain() {
  start_trace = true;
}
VOID AfterMain() {
  start_trace = false;
}

VOID CustomInstrumentation(IMG img, VOID *v)
{
  cout << "[+] Loading " << IMG_Name(img).c_str() << ", Image id = " << IMG_Id(img) << endl;
  cout << "    Low Adress : " << IMG_LowAddress(img) << ", High Address : " << IMG_HighAddress(img) << endl;

  if (IMG_IsMainExecutable(img))
  {
    LogFile << " Image Name          : " << IMG_Name(img).c_str() << endl;
    LogFile << " Image Load offset   : 0x" << IMG_LoadOffset(img) << endl;
    LogFile << " Image Low address   : 0x" << IMG_LowAddress(img) << endl;
    LogFile << " Image High address  : 0x" << IMG_HighAddress(img) << endl;
    LogFile << " Image Start address : 0x" << IMG_StartAddress(img) << endl;
    LogFile << " Image Size mapped   : " << IMG_SizeMapped(img) << endl;
    LogFile << " Image Type          : " << IMG_Type(img) << endl;

    if (EnumSymbols.Value())
      LogFile << "\n[+] Symbols List" << endl << endl;
    else
      LogFile << "\n[+] Started tracing after '" << EntryPoint.Value().c_str() << "()' call" << endl << endl;
  }

  for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
  {
    string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);

    if(EnumSymbols.Value())
    {
      LogFile << "" << undFuncName << "" << endl;
      continue;
    }

    if (undFuncName == EntryPoint.Value().c_str())
    {
      RTN allocRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

      if (RTN_Valid(allocRtn))
      {
        RTN_Open(allocRtn);

        RTN_InsertCall(allocRtn, IPOINT_BEFORE, (AFUNPTR)BeforeMain, IARG_END);
        RTN_InsertCall(allocRtn, IPOINT_AFTER, (AFUNPTR)AfterMain, IARG_END);

        RTN_Close(allocRtn);
      }
    }
    if (undFuncName == "RtlAllocateHeap")
    {
      RTN allocRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

      if (RTN_Valid(allocRtn))
      {
        RTN_Open(allocRtn);
        
        //NTSYSAPI PVOID RtlAllocateHeap(
        //  PVOID  HeapHandle,
        //  ULONG  Flags,
        //  SIZE_T Size
        //);
        RTN_InsertCall(allocRtn, IPOINT_BEFORE, (AFUNPTR)LogBeforeMalloc,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
          IARG_RETURN_IP,
          IARG_END);

        // Record RtlAllocateHeap return address and IP of caller function
        RTN_InsertCall(allocRtn, IPOINT_AFTER, (AFUNPTR)LogAfterMalloc,
          IARG_FUNCRET_EXITPOINT_VALUE, 
          IARG_RETURN_IP, 
          IARG_END);
        
        RTN_Close(allocRtn);
      }
    }
    if (undFuncName == "RtlReAllocateHeap")
    {
      RTN reallocRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

      if (RTN_Valid(reallocRtn))
      {
        RTN_Open(reallocRtn);

        //NTSYSAPI PVOID RtlReAllocateHeap(
        //  IN PVOID  HeapHandle,
        //  IN ULONG  Flags,
        //  IN PVOID  MemoryPointer,
        //  IN ULONG  Size);
        RTN_InsertCall(reallocRtn, IPOINT_BEFORE, (AFUNPTR)LogBeforeReAlloc,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
          IARG_RETURN_IP,
          IARG_END);

        // Record RtlReAllocateHeap return address and IP of caller function
        RTN_InsertCall(reallocRtn, IPOINT_AFTER, (AFUNPTR)LogAfterReAlloc,
          IARG_FUNCRET_EXITPOINT_VALUE, 
          IARG_RETURN_IP, 
          IARG_END);

        RTN_Close(reallocRtn);
      }
    }
    else if (undFuncName == "RtlFreeHeap")
    {
      RTN freeRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

      if (RTN_Valid(freeRtn))
      {
        RTN_Open(freeRtn);

        //NTSYSAPI LOGICAL RtlFreeHeap(
        //  PVOID                 HeapHandle,
        //  ULONG                 Flags,
        //  _Frees_ptr_opt_ PVOID BaseAddress
        //);
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)LogFree,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
          IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 
          IARG_RETURN_IP,
          IARG_END);

        RTN_Close(freeRtn);
      }
    }
    if (undFuncName == "VirtualAllocEx")
    {
      RTN vrallocRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

      if (RTN_Valid(vrallocRtn))
      {
        RTN_Open(vrallocRtn);

        //LPVOID WINAPI VirtualAllocEx(
        //  _In_     HANDLE hProcess,
        //  _In_opt_ LPVOID lpAddress,
        //  _In_     SIZE_T dwSize,
        //  _In_     DWORD  flAllocationType,
        //  _In_     DWORD  flProtect
        //);
        RTN_InsertCall(vrallocRtn, IPOINT_BEFORE, (AFUNPTR)LogBeforeVirtualAlloc,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
          IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 
          IARG_FUNCARG_ENTRYPOINT_VALUE, 3, 
          IARG_FUNCARG_ENTRYPOINT_VALUE, 4, 
          IARG_RETURN_IP, 
          IARG_END);

        RTN_InsertCall(vrallocRtn, IPOINT_AFTER, (AFUNPTR)LogAfterVirtualAlloc,
          IARG_FUNCRET_EXITPOINT_VALUE, IARG_RETURN_IP, IARG_END);

        RTN_Close(vrallocRtn);
      }
    }
    if (undFuncName == "VirtualFreeEx")
    {
      RTN vrfreeRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

      if (RTN_Valid(vrfreeRtn))
      {
        RTN_Open(vrfreeRtn);

        //BOOL WINAPI VirtualFreeEx(
        //  _In_ HANDLE hProcess,
        //  _In_ LPVOID lpAddress,
        //  _In_ SIZE_T dwSize,
        //  _In_ DWORD  dwFreeType
        //);
        RTN_InsertCall(vrfreeRtn, IPOINT_BEFORE, (AFUNPTR)LogBeforeVirtualFree,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
          IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
          IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 
          IARG_FUNCARG_ENTRYPOINT_VALUE, 3, 
          IARG_RETURN_IP, 
          IARG_END);

        RTN_Close(vrfreeRtn);
      }
    }
  }
}

VOID FinalFunc(INT32 code, VOID *v)
{
  for (pair<ADDRINT, bool> p : MallocMap)
  {
    if (!p.second)
      LogFile << "[*] Memory at address 0x" << hex << p.first << " allocated but not freed (memory leak)" << endl;
  }

  LogFile.close();
}

int main(int argc, char *argv[])
{
  PIN_InitSymbols();
  PIN_Init(argc, argv);

  LogFile.open(LogFileName.Value().c_str());
  LogFile << "[+] Memory tracing for PID = " << PIN_GetPid() << endl << endl;
  
  IMG_AddInstrumentFunction(CustomInstrumentation, NULL);
  PIN_AddFiniFunction(FinalFunc, NULL);
  PIN_StartProgram();

  return 0;
}

