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

#define PE_HEADER_LIMIT 0x200
#define ESTIMATED_LOOP_DELTA 0x50

#ifdef STANDALONE
#include "..\alloc.h"
extern _NtAllocateVirtualMemory pNtAllocateVirtualMemory;
#endif

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

extern int DumpPE(LPCVOID Buffer);
extern int DumpMemory(LPCVOID Buffer, unsigned int Size);
extern int ScanForPE(LPCVOID Buffer, unsigned int Size, LPCVOID* Offset);

SIZE_T AllocationSize;
PVOID AllocationBase;

PVOID *pAllocationBase;
PSIZE_T pRegionSize;

BOOL AllocationWriteDetected;
BOOL PeImageDetected;
BOOL AllocationDumped;
static BOOL AllocationBaseExecBpSet;
static BOOL EntryPointExecBpSet;
static unsigned int EPBPRegister;

static DWORD BasePointer, FirstEIP, LastEIP, CurrentEIP, LastDelta, TotalDelta, DeltaMax, LoopDeltaMax;

BOOL Trace(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    if (LastEIP)
    {
        CurrentEIP = ExceptionInfo->ContextRecord->Eip;
        
        if (CurrentEIP > LastEIP)
        {
            LastDelta = (unsigned int)(CurrentEIP - LastEIP);
        }
        else
        {
            LastDelta = (unsigned int)(LastEIP - CurrentEIP);
        }
        
        if (CurrentEIP > FirstEIP)
        {
            TotalDelta = (unsigned int)(CurrentEIP - FirstEIP);
            
            if ((unsigned int)(CurrentEIP - FirstEIP) > DeltaMax)
                DeltaMax = (unsigned int)(CurrentEIP - FirstEIP);
            
            if (LoopDeltaMax && DeltaMax > LoopDeltaMax && ExceptionInfo->ContextRecord->Ebp == BasePointer)
            // attempt dump as writing may have ended
            {
                if (!AllocationDumped && DumpPE(AllocationBase))
                {
                    AllocationDumped = TRUE;
                    DoOutputDebugString("Trace: successfully dumped from loop end at 0x%x.\n", CurrentEIP);
                    return TRUE;
                }
                else
                {
                    DoOutputDebugString("Trace: failed to dump PE module from loop end at 0x%x (loop delta 0x%x).\n", CurrentEIP, (unsigned int)(CurrentEIP - FirstEIP));
                    return FALSE;
                }            
            }
        }
        else
        {
            TotalDelta = (unsigned int)(FirstEIP - CurrentEIP);

            if (DeltaMax && DeltaMax > LoopDeltaMax)
                LoopDeltaMax = DeltaMax; 
        }
        
        // attempt dump as probably not in a loop, writing may have ended
        if (TotalDelta > ESTIMATED_LOOP_DELTA && ExceptionInfo->ContextRecord->Ebp <= BasePointer)
        {
            if (!AllocationDumped && DumpPE(AllocationBase))
            {
                AllocationDumped = TRUE;
                DoOutputDebugString("Trace: successfully dumped module 0x%x bytes after last write, EIP: 0x%x\n", TotalDelta, CurrentEIP);
                return TRUE;
            }
            else
            {
                DoOutputDebugString("Trace: failed to dump PE module 0x%x bytes after last write, EIP: 0x%x", TotalDelta, CurrentEIP);
                return FALSE;
            }
        }
        else if (!LastDelta)
        {
            //DoOutputDebugString("Trace: repeating instruction at 0x%x.\n", CurrentEIP);
            SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
        }
        else
        {
            LastEIP = CurrentEIP;
            //DoOutputDebugString("Trace: next instruction at 0x%x.\n", CurrentEIP);
            SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
        }
        
        return TRUE;
    }
    else
    {
        LastEIP = ExceptionInfo->ContextRecord->Eip;
        BasePointer = ExceptionInfo->ContextRecord->Ebp;
        FirstEIP = LastEIP;
        DeltaMax = 0;
        LoopDeltaMax = 0;
        
        DoOutputDebugString("Entering single-step mode at 0x%x.\n", FirstEIP);
        SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
        return TRUE;
    }
}

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

    if (AllocationDumped == TRUE)
    {
        DoOutputDebugString("EntryPointExecCallback: allocation already dumped, clearing breakpoint.\n");
        ContextClearAllDebugRegisters(ExceptionInfo->ContextRecord);
    }
    else if (DumpPE(AllocationBase))
    {
        AllocationDumped = TRUE;
        DoOutputDebugString("EntryPointExecCallback: successfully dumped module.\n");
        ContextClearAllDebugRegisters(ExceptionInfo->ContextRecord);        
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

    if ((DWORD)pBreakpointInfo->Address < (DWORD)AllocationBase || (DWORD)pBreakpointInfo->Address > (DWORD)AllocationBase + AllocationSize)
    {
        DoOutputDebugString("EntryPointWriteCallback: current AddressOfEntryPoint is not within allocated region. We assume it's only partially written and await further writes.\n");
        return TRUE;        
    }
    
    if (EntryPointExecBpSet == FALSE)
    {
        if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &EPBPRegister, 1, (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address), BP_EXEC, EntryPointExecCallback))
        {
            EntryPointExecBpSet = TRUE;
            DoOutputDebugString("EntryPointWriteCallback: Execution bp %d set on EntryPoint 0x%x.\n", EPBPRegister, (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
        }
        else
        {
            DoOutputDebugString("EntryPointWriteCallback: ContextSetNextAvailableBreakpoint on EntryPoint 0x%x failed\n", (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
            return FALSE;
        }
    }
    else
    {
        if (ContextSetHardwareBreakpoint(ExceptionInfo->ContextRecord, EPBPRegister, 1, (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address), BP_EXEC, EntryPointExecCallback))
        {
            EntryPointExecBpSet = TRUE;
            DoOutputDebugString("EntryPointWriteCallback: Updated EntryPoint execution bp %d to 0x%x.\n", EPBPRegister, (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
            
            // since it looks like the writing is happening at most a word at a time, let's try and catch the end of the write for another dump attempt
            //SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
        }
        else
        {
            DoOutputDebugString("EntryPointWriteCallback: ContextSetHardwareBreakpoint on updated EntryPoint 0x%x failed\n", (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
            return FALSE;
        }    
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
        PeImageDetected = TRUE;
        
        if (pNtHeader->OptionalHeader.AddressOfEntryPoint && pNtHeader->OptionalHeader.AddressOfEntryPoint < AllocationSize)
        {
            if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 1, (BYTE*)AllocationBase+pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_EXEC, EntryPointExecCallback))
            {
                DoOutputDebugString("PEHeaderWriteCallback: Execution bp set on EntryPoint 0x%x.\n", (DWORD)AllocationBase+pNtHeader->OptionalHeader.AddressOfEntryPoint);
            }
            else
            {
                DoOutputDebugString("PEHeaderWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
                ContextClearHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);        
                return FALSE;
            }            
        }
        else
        {
            if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 4, (BYTE*)&(pNtHeader->OptionalHeader.AddressOfEntryPoint), BP_WRITE, EntryPointWriteCallback))
            {
                DoOutputDebugString("PEHeaderWriteCallback: set write bp on AddressOfEntryPoint location.\n");
            }   
            else
            {
                DoOutputDebugString("PEHeaderWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
                ContextClearHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);        
                return FALSE;
            }
        }
    }
    else
    {
        DoOutputDebugString("PEHeaderWriteCallback: PE header has: 0x%x.\n", *(DWORD*)pNtHeader);
    }    
	
    
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

    if ((unsigned int)e_lfanew > PE_HEADER_LIMIT)
    {
        DoOutputDebugString("PEPointerWriteCallback: pointer to PE header too big: 0x%x (perhaps writing incomplete).\n", e_lfanew);
        return FALSE;
    }

    if (e_lfanew && (*(DWORD*)((unsigned char*)AllocationBase+e_lfanew) == IMAGE_NT_SIGNATURE))
    {
        if (DumpPE(pBreakpointInfo->Address))
        {
            AllocationDumped = TRUE;
            ContextClearAllDebugRegisters(ExceptionInfo->ContextRecord);        
            DoOutputDebugString("PEPointerWriteCallback: successfully dumped module.\n");
            return TRUE;
        }
        else
        {
            DoOutputDebugString("PEPointerWriteCallback: failed to dump PE module.\n");
        }
    }
    
    if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 4, (BYTE*)AllocationBase+e_lfanew, BP_WRITE, PEHeaderWriteCallback))
    {
        DoOutputDebugString("PEPointerWriteCallback: set write bp on e_lfanew write location.\n");
    }
    else
    {
        DoOutputDebugString("PEPointerWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
        return FALSE;
    }     
        
	DoOutputDebugString("PEPointerWriteCallback executed successfully.\n");
	
	return TRUE;
}

BOOL ShellCodeExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	LPCVOID PEPointer;
    
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

    if (ScanForPE(AllocationBase, AllocationSize, &PEPointer))
    {
        if (DumpPE(PEPointer))
        {
            AllocationDumped = TRUE;
            DoOutputDebugString("ShellCodeExecCallback: Found and dumped a PE image.\n");
            ContextClearAllDebugRegisters(ExceptionInfo->ContextRecord);
        }
        else
        {
            DoOutputDebugString("ShellCodeExecCallback: Found a PE image but failed to dump it.\n");
        }
    }
    else if (DumpMemory(AllocationBase, AllocationSize))
    {
        AllocationDumped = TRUE;
        DoOutputDebugString("ShellCodeExecCallback: Dumped region of execution.\n");
        ContextClearAllDebugRegisters(ExceptionInfo->ContextRecord);
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
    unsigned int Register;
    
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
    
    AllocationWriteDetected = TRUE;
    
    if (*(WORD*)pBreakpointInfo->Address == IMAGE_DOS_SIGNATURE)
    {
        DoOutputDebugString("BaseAddressWriteCallback: MZ header found.\n");
    
        pDosHeader = (PIMAGE_DOS_HEADER)pBreakpointInfo->Address;

        if (pDosHeader->e_lfanew && pDosHeader->e_lfanew < PE_HEADER_LIMIT && (*(DWORD*)((unsigned char*)pBreakpointInfo->Address + pDosHeader->e_lfanew) == IMAGE_NT_SIGNATURE))
        {
            //DoOutputDebugString("BaseAddressWriteCallback: PE header found.\n");
            
            PeImageDetected = TRUE;
            
            if (DumpPE(pBreakpointInfo->Address))
            {
                AllocationDumped = TRUE;
                DoOutputDebugString("BaseAddressWriteCallback: successfully dumped module.\n");
                ContextClearAllDebugRegisters(ExceptionInfo->ContextRecord);
                return TRUE;
            }
            else
            {
                DoOutputDebugString("BaseAddressWriteCallback: failed to dump PE module.\n");
            }
        }
        //e_lfanew is a long, therefore dword in size
        else if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 4, (BYTE*)&pDosHeader->e_lfanew, BP_WRITE, PEPointerWriteCallback))
        {
            DoOutputDebugString("BaseAddressWriteCallback: set write bp on e_lfanew write location: 0x%x\n", (BYTE*)&pDosHeader->e_lfanew);
        }
        else
        {
            DoOutputDebugString("BaseAddressWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
            return FALSE;
        }        
    }
    else if (*(BYTE*)pBreakpointInfo->Address == 'M') 
    {
        // Cover the case where a PE file is being written a byte at a time
        DoOutputDebugString("BaseAddressWriteCallback: M written to first byte, awaiting next byte.\n");
        
        // We do nothing and hope that the 4D byte isn't code!
    }
    else 
    {
        if (AllocationBaseExecBpSet == TRUE)
        {
            DoOutputDebugString("BaseAddressWriteCallback: allocation exec bp already set, doing nothing.\n");
            return TRUE;
        }
        
        // we add an exec breakpoint on address 0 in case it's shellcode, but leave the write bp in case it's an encrypted PE
        if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, 1, (BYTE*)AllocationBase, BP_EXEC, ShellCodeExecCallback))
        {
            AllocationBaseExecBpSet = TRUE;
            DoOutputDebugString("BaseAddressWriteCallback: Execution breakpoint %d set base address: 0x%x, AllocationBaseExecBpSet = %d\n", Register, AllocationBase, AllocationBaseExecBpSet);
        }
        else
        {
            DoOutputDebugString("BaseAddressWriteCallback: ContextSetNextAvailableBreakpoint failed to set exec bp on allocation base.\n");
            return FALSE;
        }
    }

	DoOutputDebugString("BaseAddressWriteCallback executed successfully.\n");

	return TRUE;
}

BOOL SetInitialBreakpoint(PVOID *Address, SIZE_T RegionSize)
{
    DWORD ThreadId;
    unsigned int Register;
    
    ThreadId = GetCurrentThreadId();
 
    AllocationSize = RegionSize;
    AllocationBase = Address;
    
    AllocationWriteDetected = FALSE;
    PeImageDetected = FALSE;
    AllocationDumped = FALSE;    
    AllocationBaseExecBpSet = FALSE;
    EntryPointExecBpSet = FALSE;
    
    DoOutputDebugString("SetInitialBreakpoint: AllocationBase: 0x%x, AllocationSize: 0x%x, ThreadId: 0x%x\n", AllocationBase, AllocationSize, ThreadId);
    
    if (AllocationSize == 0 || AllocationBase == NULL || ThreadId == 0)
    {
        DoOutputDebugString("SetInitialBreakpoint: Error, one of the following is NULL: 0x%x, AllocationSize: 0x%x, ThreadId: 0x%x\n", AllocationBase, AllocationSize, ThreadId);
        return FALSE;
    }
    
    if (SetNextAvailableBreakpoint(ThreadId, &Register, 2, (BYTE*)AllocationBase, BP_WRITE, BaseAddressWriteCallback))
    {
        DoOutputDebugString("SetInitialBreakpoint: Breakpoint %d set write on word at base address: 0x%x\n", Register, AllocationBase);
    }
    else
	{
        DoOutputDebugString("SetInitialBreakpoint: SetNextAvailableBreakpoint failed\n");
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
    ContextClearHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
    
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

    ContextClearHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

	ShowStack(ExceptionInfo->ContextRecord->Esp, 10);
    
    pAllocationBase = (PVOID*)*(((DWORD*)ExceptionInfo->ContextRecord->Esp)+2);
    pRegionSize     = (PSIZE_T)*(((DWORD*)ExceptionInfo->ContextRecord->Esp)+4);
    ReturnAddress   = *((DWORD*)ExceptionInfo->ContextRecord->Esp);
    
    DoOutputDebugString("pAllocationBase: 0x%x, pRegionSize: 0x%x, ReturnAddress: 0x%x\n", pAllocationBase, pRegionSize, ReturnAddress);
/*    
    // We need to get the allocation address and size after the call, so let's bpe the return address
    if (ContextSetHardwareBreakpoint(ExceptionInfo->ContextRecord, 1, 0, (BYTE*)ReturnAddress, BP_EXEC, NtAllocateVirtualMemoryReturnCallback))
    {
        DoOutputDebugString("Breakpoint (1) set pNtAllocateVirtualMemory return address: 0x%x\n", *(DWORD*)ExceptionInfo->ContextRecord->Esp);
    }
    else
	{
        DoOutputDebugString("ContextSetHardwareBreakpoint (1) failed\n");
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