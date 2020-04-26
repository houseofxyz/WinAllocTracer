#include "WinAllocTracer.h"

std::vector<alloc_chunk_t> AllocList;
ofstream LogFile;
BOOL start_trace = false;
alloc_chunk_t tmp_chunk;
std::string breakpoint_msg;
BOOL is_breakpoint_set = false;
//vector<string> ModulesList;
KNOB<string> LogFileName(KNOB_MODE_WRITEONCE, "pintool", "o", "memprofile.out", "Memory trace file name");
KNOB<string> EntryPoint(KNOB_MODE_WRITEONCE, "pintool", "entrypoint", "main", "Guest entry-point function");
KNOB<BOOL> EnumSymbols(KNOB_MODE_WRITEONCE, "pintool", "symbols", "0", "List Symbols");

VOID SetBreakpointMsg(std::string msg)
{
	is_breakpoint_set = true;
	breakpoint_msg = msg;
}

VOID BeforeMalloc(WINDOWS::HANDLE hHeap, WINDOWS::DWORD dwFlags, WINDOWS::DWORD dwSize, ADDRINT ret)
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

VOID AfterMalloc(ADDRINT addr, ADDRINT ret)
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

	for (it = AllocList.begin(); it != AllocList.end(); ++it)
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

	if (it == AllocList.end())
	{
		tmp_chunk.addr = addr;
		tmp_chunk.free = false;
		AllocList.push_back(tmp_chunk);
		LogFile << "\t\t= 0x" << hex << addr << endl;
	}

	PIN_UnlockClient();
}

VOID BeforeFree(WINDOWS::HANDLE hHeap, WINDOWS::DWORD dwFlags, ADDRINT BaseAddress, ADDRINT ret)
{
	PIN_LockClient();

	if (!start_trace)
	{
		PIN_UnlockClient();
		return;
	}

	std::vector<alloc_chunk_t>::iterator it;
	for (it = AllocList.begin(); it != AllocList.end(); ++it)
	{
		if (it->addr == BaseAddress)
		{
			if (it->free)
			{
				LogFile << "[Double Free] Memory at address 0x" << hex << BaseAddress << " has been freed more than once (Caller IP: 0x" << ret << ")" << endl;
				SetBreakpointMsg(" Breakpoint Hit! Double Free!!!");
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

	if (it == AllocList.end())
		LogFile << "[Invalid Free] Freeing unallocated memory at address 0x" << hex << BaseAddress << endl;

	PIN_UnlockClient();
}

//VOID AfterFree(VOID)
//{
//	PIN_LockClient();
//	PIN_UnlockClient();
//}

VOID BeforeReAlloc(WINDOWS::HANDLE hHeap, WINDOWS::DWORD dwFlags, ADDRINT freed_addr, WINDOWS::DWORD dwBytes, ADDRINT ret)
{
	PIN_LockClient();

	if (!start_trace)
	{
		PIN_UnlockClient();
		return;
	}

	std::vector<alloc_chunk_t>::iterator it;

	for (it = AllocList.begin(); it != AllocList.end(); ++it)
	{
		if (it->addr == freed_addr)
		{
			it->free = true;
			LogFile << "[*] RtlFreeHeap(0x" << hex << freed_addr << ") called from RtlHeapRealloc()" << endl;
			break;
		}

		if (it == AllocList.end())
			LogFile << "[-] RtlHeapRealloc could not find addr to free??? - " << freed_addr << endl;
	}

	LogFile << "[*] RtlHeapReAlloc(" << hex << hHeap << ", " << dwFlags << ", 0x" << hex << freed_addr << ", " << dec << dwBytes << ")";

	PIN_UnlockClient();
}

VOID AfterReAlloc(ADDRINT addr, ADDRINT ret)
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
	for (it = AllocList.begin(); it != AllocList.end(); ++it)
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

VOID BeforeVirtualAlloc(WINDOWS::HANDLE hProcess, ADDRINT lpAddress, WINDOWS::SIZE_T dwSize, WINDOWS::DWORD flAllocationType, WINDOWS::DWORD flProtect, ADDRINT ret)
{
	PIN_LockClient();

	if (!start_trace)
	{
		PIN_UnlockClient();
		return;
	}

	tmp_chunk.size = dwSize;
	tmp_chunk.caller = ret;

	LogFile << "[*] VirtualAllocEx(" << hex << hProcess << ", " << hex << lpAddress << ", " << dec << dwSize << ", " << dec << flAllocationType << ", " << dec << flProtect << ")";

	PIN_UnlockClient();
}

VOID AfterVirtualAlloc(ADDRINT addr, ADDRINT ret)
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

	for (it = AllocList.begin(); it != AllocList.end(); ++it)
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

	if (it == AllocList.end())
	{
		tmp_chunk.addr = addr;
		tmp_chunk.free = false;
		AllocList.push_back(tmp_chunk);
		LogFile << "\t\t= 0x" << hex << addr << endl;
	}

	PIN_UnlockClient();
}

VOID BeforeVirtualFree(WINDOWS::HANDLE hProcess, ADDRINT lpAddress, WINDOWS::SIZE_T dwSize, WINDOWS::DWORD dwFreeType, ADDRINT ret)
{
	PIN_LockClient();

	if (!start_trace)
	{
		PIN_UnlockClient();
		return;
	}

	std::vector<alloc_chunk_t>::iterator it;
	for (it = AllocList.begin(); it != AllocList.end(); ++it)
	{
		if (it->addr == lpAddress)
		{
			if (it->free)
			{
				LogFile << "[Double Free] Memory at address 0x" << hex << lpAddress << " has been freed more than once (Caller IP: 0x" << ret << ")" << endl;
				SetBreakpointMsg(" Breakpoint Hit! Double Free!!!");
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

	if (it == AllocList.end())
		LogFile << "[Invalid Free] Freeing unallocated memory at address 0x" << hex << lpAddress << endl;

	PIN_UnlockClient();
}

//VOID AfterVirtualFree(VOID)
//{
//	PIN_LockClient();
//	PIN_UnlockClient();
//}

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

VOID Image_callback(IMG img, VOID* v)
{
	printf("[+] Loading %s, Image id = %d\n", IMG_Name(img).c_str(), IMG_Id(img));
	printf("    Low Adress : %p, High Address : %p\n", IMG_LowAddress(img), IMG_HighAddress(img));

	//ModulesList.push_back(IMG_Name(img).c_str());

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

		if (EnumSymbols.Value())
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
				//	PVOID  HeapHandle,
				//	ULONG  Flags,
				//	SIZE_T Size
				//);
				RTN_InsertCall(allocRtn, IPOINT_BEFORE, (AFUNPTR)BeforeMalloc,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
					IARG_RETURN_IP,
					IARG_END);

				// Record RtlAllocateHeap return address and IP of caller function
				RTN_InsertCall(allocRtn, IPOINT_AFTER, (AFUNPTR)AfterMalloc,
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
				//	IN PVOID  HeapHandle,
				//	IN ULONG  Flags,
				//	IN PVOID  MemoryPointer,
				//	IN ULONG  Size);
				RTN_InsertCall(reallocRtn, IPOINT_BEFORE, (AFUNPTR)BeforeReAlloc,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
					IARG_RETURN_IP,
					IARG_END);

				// Record RtlReAllocateHeap return address and IP of caller function
				RTN_InsertCall(reallocRtn, IPOINT_AFTER, (AFUNPTR)AfterReAlloc,
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
				//	PVOID                 HeapHandle,
				//	ULONG                 Flags,
				//	_Frees_ptr_opt_ PVOID BaseAddress
				//);
				RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)BeforeFree,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
					IARG_RETURN_IP,
					IARG_END);

				//RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)AfterFree,
				//	IARG_END);

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
				//	_In_     HANDLE hProcess,
				//	_In_opt_ LPVOID lpAddress,
				//	_In_     SIZE_T dwSize,
				//	_In_     DWORD  flAllocationType,
				//	_In_     DWORD  flProtect
				//);
				RTN_InsertCall(vrallocRtn, IPOINT_BEFORE, (AFUNPTR)BeforeVirtualAlloc,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
					IARG_RETURN_IP,
					IARG_END);

				RTN_InsertCall(vrallocRtn, IPOINT_AFTER, (AFUNPTR)AfterVirtualAlloc,
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
				//	_In_ HANDLE hProcess,
				//	_In_ LPVOID lpAddress,
				//	_In_ SIZE_T dwSize,
				//	_In_ DWORD  dwFreeType
				//);
				RTN_InsertCall(vrfreeRtn, IPOINT_BEFORE, (AFUNPTR)BeforeVirtualFree,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
					IARG_RETURN_IP,
					IARG_END);

				//RTN_InsertCall(vrfreeRtn, IPOINT_BEFORE, (AFUNPTR)AfterVirtualFree,
				//	IARG_END);

				RTN_Close(vrfreeRtn);
			}
		}
	}
}

VOID Fini_callback(INT32 code, VOID* v)
{
	std::vector<alloc_chunk_t>::iterator it;

	for (it = AllocList.begin(); it != AllocList.end(); ++it)
	{
		if (!it->free)
			LogFile << "[Memory Leak] Memory at address 0x" << hex << it->addr << " has been allocated but not freed" << endl;
	}

	LogFile.close();
}

VOID ImageUnload_callback(IMG img, VOID* v)
{
	printf("[+] Unloading image %s\n", IMG_Name(img).c_str());
}

// used for debug
//BOOL isAddressInModule(ADDRINT addr)
//{
//	PIN_LockClient();
//	IMG img = IMG_FindByAddress(addr);
//	string path = (IMG_Valid(img) ? IMG_Name(img) : "Invalid Img");
//	auto it = std::find(ModulesList.begin(), ModulesList.end(), path);
//	
//	cout << "MODULE path: " << path << endl;
//	
//	if (it != ModulesList.end())
//	{
//		PIN_UnlockClient();
//		return TRUE;
//	}
//	else
//	{
//		PIN_UnlockClient();
//		return FALSE;
//	}
//}

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

VOID ReadWriteMem_callback(ADDRINT insAddr, std::string* insDis, UINT32 opCount, REG reg_r, ADDRINT memOp, ADDRINT sp)
{
	std::vector<alloc_chunk_t>::iterator it;
	ADDRINT addr = memOp;

	if (opCount != 2)
		return;

	if (!isAddressInMainExe(insAddr))
		return;

	for (it = AllocList.begin(); it != AllocList.end(); ++it)
	{
		if (addr >= it->addr && addr < (it->addr + it->size) && it->free == true)
		{
			LogFile << "[Use After Free] Chunk: 0x" << addr << "\tInstruction: 0x" << insAddr << "\t" << *insDis << endl;
			SetBreakpointMsg(" Breakpoint Hit! Use After Free!!!");
			return;
		}
	}
}

VOID PIN_FAST_ANALYSIS_CALL InsInstruction_callback(const CONTEXT* ctx)
{
	if (is_breakpoint_set)
	{
		if (PIN_GetDebugStatus() == DEBUG_STATUS_CONNECTED)
			PIN_ApplicationBreakpoint(ctx, PIN_ThreadId(), FALSE, breakpoint_msg);
	}
}

VOID Instruction_callback(INS ins, VOID* v)
{
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)InsInstruction_callback,
		IARG_FAST_ANALYSIS_CALL, IARG_CONST_CONTEXT,
		IARG_END);

	if (INS_OperandCount(ins) > 1 && INS_IsMemoryRead(ins) && INS_OperandIsMemory(ins, 1) && INS_OperandIsReg(ins, 0))
	{
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)ReadWriteMem_callback,
			IARG_ADDRINT, INS_Address(ins),
			IARG_PTR, new string(INS_Disassemble(ins)),
			IARG_UINT32, INS_OperandCount(ins),
			IARG_UINT32, INS_OperandReg(ins, 0),
			IARG_MEMORYOP_EA, 0,
			IARG_REG_VALUE, REG_STACK_PTR,
			IARG_END);
	}

	if (INS_OperandCount(ins) > 1 && INS_IsMemoryWrite(ins))
	{
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)ReadWriteMem_callback,
			IARG_ADDRINT, INS_Address(ins),
			IARG_PTR, new string(INS_Disassemble(ins)),
			IARG_UINT32, INS_OperandCount(ins),
			IARG_UINT32, INS_OperandReg(ins, 1),
			IARG_MEMORYOP_EA, 0,
			IARG_REG_VALUE, REG_STACK_PTR,
			IARG_END);
	}
}

int main(int argc, char* argv[])
{
	PIN_InitSymbols();
	PIN_Init(argc, argv);
	PIN_SetSyntaxIntel();

	LogFile.open(LogFileName.Value().c_str());
	LogFile << "[+] Memory tracing for PID = " << PIN_GetPid() << endl << endl;

	IMG_AddInstrumentFunction(Image_callback, NULL);
	IMG_AddUnloadFunction(ImageUnload_callback, 0);

	INS_AddInstrumentFunction(Instruction_callback, 0);

	PIN_AddFiniFunction(Fini_callback, NULL);
	PIN_StartProgram();

	return 0;
}
