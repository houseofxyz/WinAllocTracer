#pragma once
#include "pin.h"
#include <iostream>
#include <fstream>
#include <map>

namespace WINDOWS
{
#include <windows.h>
}

using namespace std;

struct alloc_chunk_t
{
  ADDRINT addr;
  BOOL free;
  WINDOWS::SIZE_T size;
  ADDRINT caller;
};

std::vector<alloc_chunk_t> MallocMap;
ofstream LogFile;
BOOL start_trace = false;
alloc_chunk_t tmp_chunk;
KNOB<string> LogFileName(KNOB_MODE_WRITEONCE, "pintool", "o", "memprofile.out", "Memory trace file name");
KNOB<string> EntryPoint(KNOB_MODE_WRITEONCE, "pintool", "entrypoint", "main", "Guest entry-point function");
KNOB<BOOL> EnumSymbols(KNOB_MODE_WRITEONCE, "pintool", "symbols", "0", "List Symbols");

