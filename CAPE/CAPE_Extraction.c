/*
CAPE - Config And Payload Extraction
Copyright(C) 2015, 2016 Context Information Security. (kevin.oreilly@contextis.com)

This program is free software : you can redistribute it and / or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.
*/
#include <windows.h>
#include "Debugger.h"

#define PE_HEADER_LIMIT 0x100

#ifdef STANDALONE
#include "..\alloc.h"
extern _NtAllocateVirtualMemory pNtAllocateVirtualMemory;
#endif

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

extern int DumpPE(LPCVOID Buffer);
extern int DumpMemory(LPCVOID Buffer, unsigned int Size);

SIZE_T AllocationSize;
PVOID AllocationBase;

PVOID *pAllocationBase;
PSIZE_T pRegionSize;

BOOL EntryPointExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("EntryPointExecCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("EntryPointExecCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("EntryPointExecCallback: Hardware breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

    if (DumpPE(AllocationBase))
    {
        DoOutputDebugString("EntryPointExecCallback: successfully dumped module.\n");
        ClearExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);        
    }
    else
    {
        DoOutputDebugString("EntryPointExecCallback: failed to dump PE module.\n");
        return FALSE;
    }
	
    DoOutputDebugString("EntryPointExecCallback executed successfully.\n");
	
	return TRUE;
}

BOOL EntryPointWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("EntryPointWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("EntryPointWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("EntryPointWriteCallback: Hardware breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

    if (SetExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, 1, 1, (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address), BP_EXEC, EntryPointExecCallback))
    {
        DoOutputDebugString("EntryPointWriteCallback: set exec bp (1) on EntryPoint 0x%x.\n", (DWORD)AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
        ClearExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);        
    }
    else
    {
        DoOutputDebugString("SetExceptionHardwareBreakpoint (1) failed\n");
        return FALSE;
    }
	
    DoOutputDebugString("EntryPointWriteCallback executed successfully.\n");
	
	return TRUE;
}

BOOL PEHeaderWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PIMAGE_NT_HEADERS32 pNtHeader;
    
    if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("PEHeaderWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("PEHeaderWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("PEHeaderWriteCallback: Hardware breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

    pNtHeader = (PIMAGE_NT_HEADERS)pBreakpointInfo->Address;
    
    if (*(DWORD*)pNtHeader == IMAGE_NT_SIGNATURE)
    {
        if (SetExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, 0, 4, (BYTE*)&(pNtHeader->OptionalHeader.AddressOfEntryPoint), BP_WRITE, EntryPointWriteCallback))
        {
            DoOutputDebugString("PEHeaderWriteCallback: set write bp (0) on AddressOfEntryPoint location.\n");
        }
        else
        {
            DoOutputDebugString("SetExceptionHardwareBreakpoint (0) failed\n");
            return FALSE;
        }
        
        if (pNtHeader->OptionalHeader.AddressOfEntryPoint && SetExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, 3, 1, (BYTE*)AllocationBase+pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_EXEC, EntryPointExecCallback))
        {
            DoOutputDebugString("PEHeaderWriteCallback: set exec bp (3) on EntryPoint 0x%x.\n", (DWORD)AllocationBase+pNtHeader->OptionalHeader.AddressOfEntryPoint);
        }
        else
        {
            DoOutputDebugString("SetExceptionHardwareBreakpoint (3) failed\n");
            return FALSE;
        }
        
    }
    else
    {
        DoOutputDebugString("PEHeaderWriteCallback: PE header has: 0x%x.\n", *(DWORD*)pNtHeader);
    }    
	
    ClearExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);        
    
    DoOutputDebugString("PEHeaderWriteCallback executed successfully.\n");
	
	return TRUE;
}

BOOL PEPointerWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	long e_lfanew;
    
    DoOutputDebugString("PEPointerWriteCallback entry.\n");
    
    if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("PEPointerWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("PEPointerWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("PEPointerWriteCallback: Hardware breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

    e_lfanew = *(long*)((pBreakpointInfo->Address));

    if ((unsigned int)e_lfanew>PE_HEADER_LIMIT)
    {
        // This check is possibly not appropriate here
        // As long as we've got what's been compressed
        return FALSE;
    }

    if (e_lfanew && (*(DWORD*)((unsigned char*)AllocationBase+e_lfanew) == IMAGE_NT_SIGNATURE))
    {
        if (DumpPE(pBreakpointInfo->Address))
        {
            ClearExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);        
            DoOutputDebugString("PEPointerWriteCallback: successfully dumped module.\n");
            return TRUE;
        }
        else
        {
            DoOutputDebugString("PEPointerWriteCallback: failed to dump PE module.\n");
        }
    }
    
    if (SetExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, 2, 4, (BYTE*)AllocationBase+e_lfanew, BP_WRITE, PEHeaderWriteCallback))
    {
        DoOutputDebugString("PEPointerWriteCallback: set write bp (2) on e_lfanew write location.\n");
        ClearExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
    }
    else
    {
        DoOutputDebugString("SetExceptionHardwareBreakpoint (2) failed\n");
        return FALSE;
    }     
        
	DoOutputDebugString("PEPointerWriteCallback executed successfully.\n");
	
	return TRUE;
}

BOOL ShellCodeExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("ShellCodeExecCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("ShellCodeExecCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("ShellCodeExecCallback: Hardware breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

    if (DumpMemory(AllocationBase, AllocationSize))
    {
        DoOutputDebugString("ShellCodeExecCallback: Dumped region of execution.\n");
        ClearExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
    }
    else
    {
        DoOutputDebugString("ShellCodeExecCallback: failed to dump PE module.\n");
        return FALSE;
    }
	
    DoOutputDebugString("ShellCodeExecCallback executed successfully.\n");
	
	return TRUE;
}

BOOL BaseAddressWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    PIMAGE_DOS_HEADER pDosHeader;
    
	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("BaseAddressWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("BaseAddressWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("BaseAddressWriteCallback: Hardware breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);
    
    if (*(WORD*)pBreakpointInfo->Address == IMAGE_DOS_SIGNATURE)
    {
        DoOutputDebugString("BaseAddressWriteCallback: MZ header found.\n");
    
        pDosHeader = (PIMAGE_DOS_HEADER)pBreakpointInfo->Address;

        if (pDosHeader->e_lfanew && (*(DWORD*)((unsigned char*)pBreakpointInfo->Address + pDosHeader->e_lfanew) == IMAGE_NT_SIGNATURE))
        {
            //DoOutputDebugString("BaseAddressWriteCallback: PE header found.\n");
            
            if (DumpPE(pBreakpointInfo->Address))
            {
                DoOutputDebugString("BaseAddressWriteCallback: successfully dumped module.\n");
                return TRUE;
            }
            else
            {
                DoOutputDebugString("BaseAddressWriteCallback: failed to dump PE module.\n");
            }
        }
        //e_lfanew is a long, therefore dword in size
        else if (SetExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, 1, 4, (BYTE*)&pDosHeader->e_lfanew, BP_WRITE, PEPointerWriteCallback))
        {
            DoOutputDebugString("BaseAddressWriteCallback: set write bp (1) on e_lfanew write location: 0x%x\n", (BYTE*)&pDosHeader->e_lfanew);
        }
        else
        {
            DoOutputDebugString("SetExceptionHardwareBreakpoint (1) failed\n");
            return FALSE;
        }        
    }
    else 
    {
        if (SetExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, 3, 1, (BYTE*)AllocationBase, BP_EXEC, ShellCodeExecCallback))
        {
            DoOutputDebugString("Breakpoint (3) set exec on base address: 0x%x\n", AllocationBase);
            ClearExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
        }
        else
        {
            DoOutputDebugString("SetExceptionHardwareBreakpoint (3) failed\n");
            return FALSE;
        }
    }
   
	ClearExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
    
	DoOutputDebugString("BaseAddressWriteCallback executed successfully.\n");

	return TRUE;
}

BOOL SetInitialBreakpoint(PVOID *Address, SIZE_T RegionSize)
{
    DWORD ThreadId;
    
    ThreadId = GetCurrentThreadId();
 
    AllocationSize = RegionSize;
    AllocationBase = Address;
    
    DoOutputDebugString("SetInitialBreakpoint: AllocationBase: 0x%x, AllocationSize: 0x%x, ThreadId: 0x%x\n", AllocationBase, AllocationSize, ThreadId);
    
    if (AllocationSize == NULL || AllocationBase == NULL || ThreadId == NULL)
    {
        DoOutputDebugString("SetInitialBreakpoint: Error, one of the following is NULL: 0x%x, AllocationSize: 0x%x, ThreadId: 0x%x\n", AllocationBase, AllocationSize, ThreadId);
        return FALSE;
    }
    
    if (SetHardwareBreakpoint(ThreadId, 0, 2, (BYTE*)AllocationBase, BP_WRITE, BaseAddressWriteCallback))
    {
        DoOutputDebugString("SetInitialBreakpoint: Breakpoint (0) set write on word at base address: 0x%x\n", AllocationBase);
    }
    else
	{
        DoOutputDebugString("SetInitialBreakpoint: SetHardwareBreakpoint (0) failed\n");
        return FALSE;
	}
    
    return TRUE;
}

#ifdef STANDALONE
// For testing purposes

void ShowStack(DWORD StackPointer, unsigned int NumberOfRecords)
{
    unsigned int i;
    
    for (i=0; i<NumberOfRecords; i++)
        DoOutputDebugString("0x%x ([esp+0x%x]): 0x%x\n", StackPointer+4*i, (4*i), *(DWORD*)((BYTE*)StackPointer+4*i));
}


BOOL NtAllocateVirtualMemoryReturnCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    ClearExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
    
	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("NtAllocateVirtualMemoryReturnCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("NtAllocateVirtualMemoryReturnCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("NtAllocateVirtualMemoryReturnCallback: Hardware breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);
	
    SetInitialBreakpoint(*pAllocationBase, *pRegionSize);
    
    return TRUE;
}

BOOL NtAllocateVirtualMemoryCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	DWORD ReturnAddress;
	
    if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("NtAllocateVirtualMemoryCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("NtAllocateVirtualMemoryCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("NtAllocateVirtualMemoryCallback: Hardware breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

    ClearExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

	ShowStack(ExceptionInfo->ContextRecord->Esp, 10);
    
    pAllocationBase = (PVOID*)*(((DWORD*)ExceptionInfo->ContextRecord->Esp)+2);
    pRegionSize     = (PSIZE_T)*(((DWORD*)ExceptionInfo->ContextRecord->Esp)+4);
    ReturnAddress   = *((DWORD*)ExceptionInfo->ContextRecord->Esp);
    
    DoOutputDebugString("pAllocationBase: 0x%x, pRegionSize: 0x%x, ReturnAddress: 0x%x\n", pAllocationBase, pRegionSize, ReturnAddress);
/*    
    // We need to get the allocation address and size after the call, so let's bpe the return address
    if (SetExceptionHardwareBreakpoint(ExceptionInfo->ContextRecord, 1, 0, (BYTE*)ReturnAddress, BP_EXEC, NtAllocateVirtualMemoryReturnCallback))
    {
        DoOutputDebugString("Breakpoint (1) set pNtAllocateVirtualMemory return address: 0x%x\n", *(DWORD*)ExceptionInfo->ContextRecord->Esp);
    }
    else
	{
        DoOutputDebugString("SetExceptionHardwareBreakpoint (1) failed\n");
        return FALSE;
	}    
*/
    return TRUE;
}

BOOL SetNtAllocateVirtualMemoryBP()
{
    DWORD ThreadId;
    
    ThreadId = GetCurrentThreadId();
    
    DoOutputDebugString("SetNtAllocateVirtualMemoryBP entry\n");
    
    if (SetHardwareBreakpoint(ThreadId, 0, 1, (BYTE*)pNtAllocateVirtualMemory, BP_EXEC, NtAllocateVirtualMemoryCallback))
    {
        DoOutputDebugString("Breakpoint (0) set exec on pNtAllocateVirtualMemory: 0x%x\n", pNtAllocateVirtualMemory);
    }
    else
	{
        DoOutputDebugString("SetHardwareBreakpoint (0) failed\n");
        return FALSE;
	}
    
    return TRUE;
}
#endif