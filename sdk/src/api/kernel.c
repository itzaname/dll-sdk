#include "api.h"

// Func addrs
PVOID pBeep = NULL;
PVOID pGetProcessHeap = NULL;
PVOID pHeapAlloc = NULL;

// Beep implementation
void Beep(DWORD freq, DWORD dur)
{
	typedef BOOL(__stdcall *pBeepFunc)(DWORD Frequency, DWORD Duration);
	if (pBeep == NULL)
        pBeep = GetProcAddress(GetKernel32Base(),"Beep");

	if (pBeep != NULL)
		((pBeepFunc)(pBeep))(freq,dur);
}

// Retrieves a handle to the default heap of the calling process.
// This handle can then be used in subsequent calls to the heap functions.
HANDLE GetProcessHeap()
{
    typedef HANDLE(__stdcall *pGetProcessHeapFunc)(void);
    if (pGetProcessHeap == NULL)
        pGetProcessHeap = GetProcAddress(GetKernel32Base(),"GetProcessHeap");

    if (pGetProcessHeap != NULL)
        return ((pGetProcessHeapFunc)(pGetProcessHeap))();

    return NULL;
}

// Allocates a block of memory from a heap. The allocated memory is not movable.
LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    typedef LPVOID(__stdcall *pHeapAllocFunc)(HANDLE,DWORD,SIZE_T);
    if (pHeapAlloc == NULL)
        pHeapAlloc = GetProcAddress(GetKernel32Base(),"HeapAlloc");

    if (HeapAlloc != NULL)
        return ((pHeapAllocFunc)(pHeapAlloc))(hHeap, dwFlags, dwBytes);

    return NULL;
}