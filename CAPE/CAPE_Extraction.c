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
#include "CAPE.h"

#define PE_HEADER_LIMIT 0x200
#define ESTIMATED_LOOP_DELTA 0x50

#ifdef STANDALONE
#include "..\alloc.h"
extern _NtAllocateVirtualMemory pNtAllocateVirtualMemory;
#endif

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

extern int DumpImageInCurrentProcess(DWORD ModuleBase);
extern int DumpMemory(LPCVOID Buffer, unsigned int Size);
extern int ScanForPE(LPCVOID Buffer, unsigned int Size, LPCVOID* Offset);

SIZE_T AllocationSize;
PVOID AllocationBase;

PVOID *pAllocationBase;
PSIZE_T pRegionSize;

BOOL AllocationWriteDetected;
BOOL PeImageDetected;
BOOL AllocationDumped;
BOOL AllocationBaseWriteBpSet;
BOOL AllocationBaseExecBpSet;
BOOL EntryPointExecBpSet;
static unsigned int EPBPRegister;

static DWORD BasePointer, FirstEIP, LastEIP, CurrentEIP, LastDelta, TotalDelta, DeltaMax, LoopDeltaMax;

void ExtractionClearAll(void)
{
    if (AllocationBase && AllocationSize)
        ClearBreakpointsInRange(GetCurrentThreadId(), AllocationBase, AllocationSize);                       
    
    AllocationSize = 0;
    AllocationBase = NULL;
    CapeMetaData->Address = NULL;
    
    AllocationWriteDetected = FALSE;
    PeImageDetected = FALSE;
    AllocationBaseExecBpSet = FALSE;
    EntryPointExecBpSet = FALSE;
    
    return;
}
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
                SetCapeMetaData(EXTRACTION_PE, 0, NULL, AllocationBase);

                if (!AllocationDumped && DumpImageInCurrentProcess((DWORD)AllocationBase))
                {
                    AllocationDumped = TRUE;
                    DoOutputDebugString("Trace: successfully dumped from loop end at 0x%x.\n", CurrentEIP);
                    ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);       
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
            SetCapeMetaData(EXTRACTION_PE, 0, NULL, AllocationBase);
            
            if (!AllocationDumped && DumpImageInCurrentProcess((DWORD)AllocationBase))
            {
                AllocationDumped = TRUE;
                DoOutputDebugString("Trace: successfully dumped module 0x%x bytes after last write, EIP: 0x%x\n", TotalDelta, CurrentEIP);
                ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);       
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

	DoOutputDebugString("EntryPointExecCallback: Breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

    SetCapeMetaData(EXTRACTION_PE, 0, NULL, AllocationBase);

    if (AllocationDumped == TRUE)
    {
        DoOutputDebugString("EntryPointExecCallback: allocation already dumped, clearing breakpoint.\n");
        ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);
    }
    else if (DumpImageInCurrentProcess((DWORD)AllocationBase))
    {
        AllocationDumped = TRUE;
        DoOutputDebugString("EntryPointExecCallback: successfully dumped module.\n");       
        ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);        
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

	DoOutputDebugString("EntryPointWriteCallback: Breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

    if ((DWORD)pBreakpointInfo->Address < (DWORD)AllocationBase || (DWORD)pBreakpointInfo->Address > (DWORD)AllocationBase + AllocationSize)
    {
        DoOutputDebugString("EntryPointWriteCallback: current AddressOfEntryPoint is not within allocated region. We assume it's only partially written and await further writes.\n");
        return TRUE;        
    }
    
    if (EntryPointExecBpSet == FALSE)
    {
        if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &EPBPRegister, 0, (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address), BP_EXEC, EntryPointExecCallback))
        {
            EntryPointExecBpSet = TRUE;
            DoOutputDebugString("EntryPointWriteCallback: Execution bp %d set on EntryPoint 0x%x (EIP = 0x%x).\n", EPBPRegister, (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address), ExceptionInfo->ContextRecord->Eip);
        }
        else
        {
            DoOutputDebugString("EntryPointWriteCallback: ContextSetNextAvailableBreakpoint on EntryPoint 0x%x failed\n", (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
            return FALSE;
        }
    }
    else
    {
        if (ContextSetBreakpoint(ExceptionInfo->ContextRecord, EPBPRegister, 0, (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address), BP_EXEC, EntryPointExecCallback))
        {
            EntryPointExecBpSet = TRUE;
            DoOutputDebugString("EntryPointWriteCallback: Updated EntryPoint execution bp %d to 0x%x (EIP = 0x%x).\n", EPBPRegister, (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address), ExceptionInfo->ContextRecord->Eip);
            
            // since it looks like the writing is happening at most a word at a time, let's try and catch the end of the write for another dump attempt
            //SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
        }
        else
        {
            DoOutputDebugString("EntryPointWriteCallback: ContextSetBreakpoint on updated EntryPoint 0x%x failed\n", (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
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

	DoOutputDebugString("PEHeaderWriteCallback: Breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

    pNtHeader = (PIMAGE_NT_HEADERS)pBreakpointInfo->Address;
    
    if (*(DWORD*)pNtHeader == IMAGE_NT_SIGNATURE)
    {
        PeImageDetected = TRUE;
        
        if (pNtHeader->OptionalHeader.AddressOfEntryPoint && pNtHeader->OptionalHeader.AddressOfEntryPoint < AllocationSize)
        {
            if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 0, (BYTE*)AllocationBase+pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_EXEC, EntryPointExecCallback))
            {
                DoOutputDebugString("PEHeaderWriteCallback: Execution bp set on EntryPoint 0x%x (EIP = 0x%x).\n", (DWORD)AllocationBase+pNtHeader->OptionalHeader.AddressOfEntryPoint, ExceptionInfo->ContextRecord->Eip);
            }
            else
            {
                DoOutputDebugString("PEHeaderWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
                ContextClearBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);        
                return FALSE;
            }            
        }
        else
        {
            if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(DWORD), (BYTE*)&(pNtHeader->OptionalHeader.AddressOfEntryPoint), BP_WRITE, EntryPointWriteCallback))
            {
                DoOutputDebugString("PEHeaderWriteCallback: set write bp on AddressOfEntryPoint location (EIP = 0x%x).\n", ExceptionInfo->ContextRecord->Eip);
            }   
            else
            {
                DoOutputDebugString("PEHeaderWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
                ContextClearBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);        
                return FALSE;
            }
        }
    }
    else if (*(BYTE*)pBreakpointInfo->Address == 'P') 
    {
        // Cover the case where PE file is being written a byte at a time
        DoOutputDebugString("PEHeaderWriteCallback: P written to first byte, awaiting next byte.\n");
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

	DoOutputDebugString("PEPointerWriteCallback: Breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

    e_lfanew = *(long*)((pBreakpointInfo->Address));

    if ((unsigned int)e_lfanew > PE_HEADER_LIMIT)
    {
        DoOutputDebugString("PEPointerWriteCallback: pointer to PE header too big: 0x%x (perhaps writing incomplete).\n", e_lfanew);
        return FALSE;
    }

    SetCapeMetaData(EXTRACTION_PE, 0, NULL, AllocationBase);

    if (e_lfanew && (*(DWORD*)((unsigned char*)AllocationBase+e_lfanew) == IMAGE_NT_SIGNATURE))
    {
        if (DumpImageInCurrentProcess((DWORD)pBreakpointInfo->Address))
        {
            AllocationDumped = TRUE;
            ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);        
            DoOutputDebugString("PEPointerWriteCallback: successfully dumped module.\n");
            return TRUE;
        }
        else
        {
            DoOutputDebugString("PEPointerWriteCallback: failed to dump PE module.\n");
        }
    }
    
    if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(DWORD), (BYTE*)AllocationBase+e_lfanew, BP_WRITE, PEHeaderWriteCallback))
    {
        DoOutputDebugString("PEPointerWriteCallback: set write bp on e_lfanew write location 0x%x (EIP = 0x%x)\n", (BYTE*)AllocationBase + e_lfanew, ExceptionInfo->ContextRecord->Eip);
    }
    else
    {
        DoOutputDebugString("PEPointerWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
        return FALSE;
    }     
        
	DoOutputDebugString("PEPointerWriteCallback executed successfully.\n");
	
	return TRUE;
}

BOOL MidPageExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	MEMORY_BASIC_INFORMATION MemInfo;
	LPCVOID PEPointer;
    
    if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("MidPageExecCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("MidPageExecCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("MidPageExecCallback: Breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

    memset(&MemInfo, 0, sizeof(MemInfo));

    VirtualQuery(pBreakpointInfo->Address, &MemInfo, sizeof(MemInfo));
    
    DoOutputDebugString("MidPageExecCallback: Debug: About to scan region for a PE image (base 0x%x, size 0x%x).\n", MemInfo.AllocationBase, MemInfo.RegionSize);

    SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, AllocationBase);
    
    if (ScanForPE(MemInfo.AllocationBase, MemInfo.RegionSize, &PEPointer))
    {
        SetCapeMetaData(EXTRACTION_PE, 0, NULL, AllocationBase);

        if (DumpImageInCurrentProcess((DWORD)PEPointer))
        {
            DoOutputDebugString("MidPageExecCallback: Found and dumped a PE image.\n");
            ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);
        }
        else
        {
            DoOutputDebugString("MidPageExecCallback: Found a PE image but failed to dump it.\n");
        }
    }
    else if (DumpMemory(MemInfo.AllocationBase, MemInfo.RegionSize))
    {
        DoOutputDebugString("MidPageExecCallback: Dumped region of execution.\n");
        ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);
    }
    else
    {
        DoOutputDebugString("MidPageExecCallback: failed to dump PE module.\n");
        return FALSE;
    }
	
    DoOutputDebugString("MidPageExecCallback executed successfully.\n");
	
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

	DoOutputDebugString("ShellCodeExecCallback: Breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

    SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, AllocationBase);

    if (ScanForPE(AllocationBase, AllocationSize, &PEPointer))
    {
        SetCapeMetaData(EXTRACTION_PE, 0, NULL, AllocationBase);

        if (DumpImageInCurrentProcess((DWORD)PEPointer))
        {
            AllocationDumped = TRUE;
            DoOutputDebugString("ShellCodeExecCallback: Found and dumped a PE image.\n");
            ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);
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
        ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);
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

	DoOutputDebugString("BaseAddressWriteCallback: Breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);
    
    AllocationWriteDetected = TRUE;
    
    if (*(WORD*)pBreakpointInfo->Address == IMAGE_DOS_SIGNATURE)
    {
        DoOutputDebugString("BaseAddressWriteCallback: MZ header found.\n");
    
        pDosHeader = (PIMAGE_DOS_HEADER)pBreakpointInfo->Address;

        if (pDosHeader->e_lfanew && (unsigned int)pDosHeader->e_lfanew < PE_HEADER_LIMIT)
        {
            if (*(DWORD*)((unsigned char*)pDosHeader + pDosHeader->e_lfanew) == IMAGE_NT_SIGNATURE)
            {
                PeImageDetected = TRUE;

                SetCapeMetaData(EXTRACTION_PE, 0, NULL, AllocationBase);
                
                if (DumpImageInCurrentProcess((DWORD)pBreakpointInfo->Address))
                {
                    AllocationDumped = TRUE;
                    DoOutputDebugString("BaseAddressWriteCallback: successfully dumped module.\n");
                    ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);
                    return TRUE;
                }
                else
                {
                    DoOutputDebugString("BaseAddressWriteCallback: failed to dump PE module.\n");
                }
            }
            else
            {
                // Deal with the situation where the breakpoint triggers after e_lfanew has already been written
                if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(DWORD), (BYTE*)pDosHeader + pDosHeader->e_lfanew, BP_WRITE, PEHeaderWriteCallback))
                {
                    DoOutputDebugString("BaseAddressWriteCallback: set write bp on e_lfanew write location 0x%x (EIP = 0x%x)\n", (BYTE*)pDosHeader + pDosHeader->e_lfanew, ExceptionInfo->ContextRecord->Eip);
                }
                else
                {
                    DoOutputDebugString("BaseAddressWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
                    return FALSE;
                }
            }
        }
        //e_lfanew is a long, therefore dword in size
        else if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(DWORD), (BYTE*)&pDosHeader->e_lfanew, BP_WRITE, PEPointerWriteCallback))
        {
            DoOutputDebugString("BaseAddressWriteCallback: set write bp on e_lfanew write location: 0x%x (EIP = 0x%x)\n", (BYTE*)&pDosHeader->e_lfanew, ExceptionInfo->ContextRecord->Eip);
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
        if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, 0, (BYTE*)AllocationBase, BP_EXEC, MidPageExecCallback))
        {
            AllocationBaseExecBpSet = TRUE;
            DoOutputDebugString("BaseAddressWriteCallback: Execution breakpoint %d set base address: 0x%x, AllocationBaseExecBpSet = %d (EIP = 0x%x)\n", Register, AllocationBase, AllocationBaseExecBpSet, ExceptionInfo->ContextRecord->Eip);
        }
        else
        {
            if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 0, (BYTE*)AllocationBase, BP_EXEC, MidPageExecCallback))
            {
                AllocationBaseExecBpSet = TRUE;
                DoOutputDebugString("BaseAddressWriteCallback: Unable to add additional breakpoint, replacing existing write bp with execution bp.\n");
            }
            else
            {
                DoOutputDebugString("BaseAddressWriteCallback: Error: Failed to replace existing write bp with execution bp.\n");
                return FALSE;
            }
        }
    }

	DoOutputDebugString("BaseAddressWriteCallback executed successfully.\n");

	return TRUE;
}

BOOL SetMidPageBreakpoint(PVOID *Address, SIZE_T Size)
{
    DWORD ThreadId;
    unsigned int Register;
    
    ThreadId = GetCurrentThreadId();
 
    AllocationSize = Size;
    AllocationBase = Address;
    CapeMetaData->Address = Address;
    
    AllocationWriteDetected = FALSE;
    PeImageDetected = FALSE;
    AllocationDumped = FALSE;    
    AllocationBaseExecBpSet = FALSE;
    EntryPointExecBpSet = FALSE;

    DoOutputDebugString("SetMidPageBreakpoint: AllocationBase: 0x%x, AllocationSize: 0x%x, ThreadId: 0x%x\n", AllocationBase, AllocationSize, ThreadId);
    
    if (AllocationSize == 0 || AllocationBase == NULL || ThreadId == 0)
    {
        DoOutputDebugString("SetMidPageBreakpoint: Error, one of the following is NULL: 0x%x, AllocationSize: 0x%x, ThreadId: 0x%x\n", AllocationBase, AllocationSize, ThreadId);
        return FALSE;
    }
    
    if (!SetNextAvailableBreakpoint(ThreadId, &Register, 0, (BYTE*)Address, BP_EXEC, MidPageExecCallback))
    {
        DoOutputDebugString("SetMidPageBreakpoint: SetNextAvailableBreakpoint failed to set exec bp on executable address 0x%x.\n", Address);
        return FALSE;
    }
    else
    {
        DoOutputDebugString("SetMidPageBreakpoint: Set exec breakpoint on protected address: 0x%x\n", Address);
    } 
    
    return TRUE;
}

BOOL SetInitialWriteBreakpoint(PVOID *Address, SIZE_T RegionSize)
{
    DWORD ThreadId;
    unsigned int Register;
    
    ThreadId = GetCurrentThreadId();
 
    AllocationSize = RegionSize;
    AllocationBase = Address;
    CapeMetaData->Address = Address;
    
    AllocationWriteDetected = FALSE;
    PeImageDetected = FALSE;
    AllocationDumped = FALSE;    
    AllocationBaseWriteBpSet = FALSE;
    AllocationBaseExecBpSet = FALSE;
    EntryPointExecBpSet = FALSE;
    
    DoOutputDebugString("SetInitialWriteBreakpoint: AllocationBase: 0x%x, AllocationSize: 0x%x, ThreadId: 0x%x\n", AllocationBase, AllocationSize, ThreadId);
    
    if (AllocationSize == 0 || AllocationBase == NULL || ThreadId == 0)
    {
        DoOutputDebugString("SetInitialWriteBreakpoint: Error, one of the following is NULL: 0x%x, AllocationSize: 0x%x, ThreadId: 0x%x\n", AllocationBase, AllocationSize, ThreadId);
        return FALSE;
    }
    
    if (SetNextAvailableBreakpoint(ThreadId, &Register, sizeof(WORD), (BYTE*)AllocationBase, BP_WRITE, BaseAddressWriteCallback))
    {
        DoOutputDebugString("SetInitialWriteBreakpoint: Breakpoint %d set write on word at base address: 0x%x\n", Register, AllocationBase);
        AllocationBaseWriteBpSet = TRUE;
    }
    else
	{
        DoOutputDebugString("SetInitialWriteBreakpoint: SetNextAvailableBreakpoint failed\n");
        return FALSE;
	}
    
    return TRUE;
}