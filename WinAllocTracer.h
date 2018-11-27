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
