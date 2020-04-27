#pragma once
#include "pin.h"
namespace WINDOWS
{
#include <windows.h>
}
#include <iostream>
#include <fstream>
#include <map>
#include <string>

using namespace std;

struct alloc_chunk_t
{
    ADDRINT addr;
    BOOL free;
    WINDOWS::SIZE_T size;
    ADDRINT caller;
};
