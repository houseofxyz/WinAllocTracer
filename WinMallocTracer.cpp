#include "WinMallocTracer.h"

VOID LogBeforeMalloc(WINDOWS::HANDLE hHeap, WINDOWS::DWORD dwFlags, WINDOWS::DWORD dwSize, ADDRINT ret)
{
  PIN_LockClient();

  if (!start_trace)
  {
    PIN_UnlockClient();
    return;
  }

  tmp_chunk.size = dwSize;
  tmp_chunk.caller = ret;

  LogFile << "[*] RtlAllocateHeap(" << hex << hHeap << ", " << dwFlags << ", " << dec << dwSize << ")";

  PIN_UnlockClient();
}

VOID LogAfterMalloc(ADDRINT addr, ADDRINT ret)
{
  PIN_LockClient();

  if (!start_trace)
  {
    PIN_UnlockClient();
    return;
  }

  if (addr == NULL)
  {
    cerr << "[-] Error: RtlAllocateHeap() return value was NULL.";
    PIN_UnlockClient();
    return;
  }

  std::vector<alloc_chunk_t>::iterator it;

  for (it = MallocMap.begin(); it != MallocMap.end(); ++it)
  {
    if (it->addr == addr)
    {
      if (it->free)
        it->free = false;
      else
        cerr << "[-] Error: allocating memory not freed!?!" << endl;

      break;
    }
  }

  if (it == MallocMap.end())
  {
    tmp_chunk.addr = addr;
    tmp_chunk.free = false;
    MallocMap.push_back(tmp_chunk);
    LogFile << "\t\t= 0x" << hex << addr << endl;
  }
  
  PIN_UnlockClient();
}

VOID LogBeforeFree(WINDOWS::HANDLE hHeap, WINDOWS::DWORD dwFlags, ADDRINT BaseAddress, ADDRINT ret)
{
  PIN_LockClient();

  if (!start_trace)
  {
    PIN_UnlockClient();
    return;
  }

  std::vector<alloc_chunk_t>::iterator it;
  for (it = MallocMap.begin(); it != MallocMap.end(); ++it)
  {
    if (it->addr == BaseAddress)
    {
      if (it->free)
      {
        LogFile << "[Double Free] Memory at address 0x" << hex << BaseAddress << " has been freed more than once (Caller IP: 0x" << ret << ")" << endl;
        break;
      }
      else
      {
        it->free = true;
        LogFile << "[*] RtlFreeHeap(" << hex << hHeap << ", " << dwFlags << ", 0x" << hex << BaseAddress << ")" << endl;
        break;
      }
    }
  }

  if (it == MallocMap.end())
    LogFile << "[Invalid Free] Freeing unallocated memory at address 0x" << hex << BaseAddress << endl;
  
  PIN_UnlockClient();
}

VOID LogBeforeReAlloc(WINDOWS::HANDLE hHeap, WINDOWS::DWORD dwFlags, ADDRINT freed_addr, WINDOWS::DWORD dwBytes, ADDRINT ret)
{
  PIN_LockClient();

  if (!start_trace)
  {
    PIN_UnlockClient();
    return;
  }

  std::vector<alloc_chunk_t>::iterator it;

  for (it = MallocMap.begin(); it != MallocMap.end(); ++it)
  {
    if (it->addr == freed_addr)
    {
      it->free = true;
      LogFile << "[*] RtlFreeHeap(0x" << hex << freed_addr << ") called from RtlHeapRealloc()" << endl;
      break;
    }

    if (it == MallocMap.end())
      LogFile << "[-] RtlHeapRealloc could not find addr to free??? - " << freed_addr << endl;
  }

  LogFile << "[*] RtlHeapReAlloc(" << hex << hHeap << ", " << dwFlags << ", 0x" << hex << freed_addr << ", " << dec << dwBytes << ")";
  
  PIN_UnlockClient();
}

VOID LogAfterReAlloc(ADDRINT addr, ADDRINT ret)
{
  PIN_LockClient();

  if (!start_trace)
  {
    PIN_UnlockClient();
    return;
  }

  if (addr == NULL)
  {
    PIN_UnlockClient();
    return;
  }

  std::vector<alloc_chunk_t>::iterator it;
  for (it = MallocMap.begin(); it != MallocMap.end(); ++it)
  {
    if (it->addr == addr)
    {
      if (it->free)
        it->free = false;
      else
        LogFile << "\t\t= 0x" << hex << addr << endl;
    }
  }
  
  PIN_UnlockClient();
}

VOID LogBeforeVirtualAlloc(WINDOWS::HANDLE hProcess, ADDRINT lpAddress, WINDOWS::SIZE_T dwSize, WINDOWS::DWORD flAllocationType, WINDOWS::DWORD flProtect, ADDRINT ret)
{
  PIN_LockClient();

  if (!start_trace)
  {
    PIN_UnlockClient();
    return;
  }

  tmp_chunk.size = dwSize;
  tmp_chunk.caller = ret;

  LogFile << "[*] VirtualAllocEx(" << hex << hProcess << ", " << hex << lpAddress << ", " << dec << dwSize << ", " << dec << flAllocationType << ", " << dec << flProtect <<")";
  
  PIN_UnlockClient();
}

VOID LogAfterVirtualAlloc(ADDRINT addr, ADDRINT ret)
{
  PIN_LockClient();

  if (!start_trace)
  {
    PIN_UnlockClient();
    return;
  }

  if (addr == NULL)
  {
    cerr << "[-] Error: VirtualAllocEx() return value was NULL.";
    PIN_UnlockClient();
    return;
  }

  std::vector<alloc_chunk_t>::iterator it;
  
  for (it = MallocMap.begin(); it != MallocMap.end(); ++it)
  {
    if (it->addr == addr)
    {
      if(it->free)
        it->free = false;
      else
        cerr << "[-] Error: allocating memory not freed!?!" << endl;

      break;
    }
  }

  if (it == MallocMap.end())
  {
    tmp_chunk.addr = addr;
    tmp_chunk.free = false;
    MallocMap.push_back(tmp_chunk);
    LogFile << "\t\t= 0x" << hex << addr << endl;
  }
  
  PIN_UnlockClient();
}

VOID LogBeforeVirtualFree(WINDOWS::HANDLE hProcess, ADDRINT lpAddress, WINDOWS::SIZE_T dwSize, WINDOWS::DWORD dwFreeType, ADDRINT ret)
{
  PIN_LockClient();

  if (!start_trace)
  {
    PIN_UnlockClient();
    return;
  }

  std::vector<alloc_chunk_t>::iterator it;
  for (it = MallocMap.begin(); it != MallocMap.end(); ++it)
  {
    if (it->addr == lpAddress)
    {
      if(it->free)
      {
        LogFile << "[Double Free] Memory at address 0x" << hex << lpAddress << " has been freed more than once (Caller IP: 0x" << ret << ")" << endl;
        break;
      }
      else
      {
        it->free = true;
        LogFile << "[*] VirtualFreeEx(" << hex << hProcess << ", 0x" << hex << lpAddress << ", " << dwSize << ", " << dwFreeType << ")" << endl;
        break;
      }
    }
  }
  
  if (it == MallocMap.end())
    LogFile << "[Invalid Free] Freeing unallocated memory at address 0x" << hex << lpAddress << endl;
  
  PIN_UnlockClient();
}

VOID BeforeMain() {
  PIN_LockClient();

  start_trace = true;

  PIN_UnlockClient();
}
VOID AfterMain() {
  PIN_LockClient();

  start_trace = false;

  PIN_UnlockClient();
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
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)LogBeforeFree,
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
  std::vector<alloc_chunk_t>::iterator it;

  for (it = MallocMap.begin(); it != MallocMap.end(); ++it)
  {
    if (!it->free)
      LogFile << "[Memory Leak] Memory at address 0x" << hex << it->addr << " has been allocated but not freed" << endl;
  }

  LogFile.close();
}

VOID image_unload_callback(IMG img, VOID *v)
{
  cout << "Unloading image" << IMG_Name(img).c_str() << endl;
}

BOOL isAddressInMainExe(ADDRINT addr)
{
  PIN_LockClient();
  IMG img = IMG_FindByAddress(addr);
  BOOL ret;
  
  if (IMG_IsMainExecutable(img))
    ret = TRUE;
  else
    ret = FALSE;

  PIN_UnlockClient();
  return ret;
}

VOID ReadWriteMem(ADDRINT insAddr, std::string *insDis, UINT32 opCount, REG reg_r, ADDRINT memOp, ADDRINT sp)
{
  std::vector<alloc_chunk_t>::iterator it;
  ADDRINT addr = memOp;

  if (opCount != 2)
    return;

  if (!isAddressInMainExe(insAddr))
    return;

  for (it = MallocMap.begin(); it != MallocMap.end(); ++it) {
    if (addr >= it->addr && addr < (it->addr + it->size) && it->free == true) 
    {
      LogFile << "[Use After Free] Chunk: 0x" << addr << "\tInstruction: 0x" << insAddr << "\t" << *insDis << endl;
      return;
    }
  }
}

VOID Instruction(INS ins, VOID *v)
{
  if (INS_OperandCount(ins) > 1 && INS_IsMemoryRead(ins) && INS_OperandIsMemory(ins, 1) && INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(
      ins, IPOINT_BEFORE, (AFUNPTR)ReadWriteMem,
      IARG_ADDRINT, INS_Address(ins),
      IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_UINT32, INS_OperandCount(ins),
      IARG_UINT32, INS_OperandReg(ins, 0),
      IARG_MEMORYOP_EA, 0,
      IARG_REG_VALUE, REG_STACK_PTR,
      IARG_END);
  }

  if (INS_OperandCount(ins) > 1 && INS_IsMemoryWrite(ins)) {
    INS_InsertCall(
      ins, IPOINT_BEFORE, (AFUNPTR)ReadWriteMem,
      IARG_ADDRINT, INS_Address(ins),
      IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_UINT32, INS_OperandCount(ins),
      IARG_UINT32, INS_OperandReg(ins, 1),
      IARG_MEMORYOP_EA, 0,
      IARG_REG_VALUE, REG_STACK_PTR,
      IARG_END);
  }
}

int main(int argc, char *argv[])
{
  PIN_InitSymbols();
  PIN_Init(argc, argv);
  PIN_SetSyntaxIntel();

  LogFile.open(LogFileName.Value().c_str());
  LogFile << "[+] Memory tracing for PID = " << PIN_GetPid() << endl << endl;

  IMG_AddInstrumentFunction(CustomInstrumentation, NULL);
  IMG_AddUnloadFunction(image_unload_callback, 0);

  INS_AddInstrumentFunction(Instruction, 0);

  PIN_AddFiniFunction(FinalFunc, NULL);
  PIN_StartProgram();

  return 0;
}

