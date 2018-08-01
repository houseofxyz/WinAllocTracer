#include <windows.h>
#include <stdio.h>

#define PAGELIMIT 80

void my_simple_uaf()
{
  char *buffer;
  char c;
  buffer = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32);
  
  c = buffer[0];
  HeapFree(GetProcessHeap(), 0, buffer);
  c = buffer[10];           /* UAF reading */
  buffer[20] = c;           /* UAF writing */
  buffer = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 64);
  c = buffer[0];
}

int my_heap_functions() {
  HLOCAL h1 = 0, h2 = 0, h3 = 0, h4 = 0;

  h1 = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 128);
  h2 = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 256);
  
  HeapFree(GetProcessHeap(), 0, h1);

  h3 = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 512);

  h4 = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, h3, 1024);
  HeapFree(GetProcessHeap(), 0, h4);

  return 0;
}

int my_double_free() {
  LPVOID lpvBase;
  DWORD dwPageSize;
  BOOL bSuccess;
  SYSTEM_INFO sSysInfo;

  GetSystemInfo(&sSysInfo);
  dwPageSize = sSysInfo.dwPageSize;

  lpvBase = VirtualAlloc(
    NULL,
    PAGELIMIT*dwPageSize,
    MEM_RESERVE,
    PAGE_NOACCESS);

  if (lpvBase == NULL)
    exit("VirtualAlloc reserve failed.");

  bSuccess = VirtualFree(
    lpvBase,
    0,
    MEM_RELEASE);

  bSuccess = VirtualFree(
    lpvBase,
    0,
    MEM_RELEASE);

  return 0;
}

int main(void) {
  my_simple_uaf();
  my_heap_functions();
  my_double_free();

  return 0;
}
