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

extern ULONG_PTR g_our_dll_base;
extern DWORD g_our_dll_size;

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

extern unsigned int address_is_in_stack(DWORD Address);

extern BOOL DumpPEsInRange(LPVOID Buffer, SIZE_T Size);
extern int DumpMemory(LPVOID Buffer, unsigned int Size);
extern int ScanForPE(LPVOID Buffer, unsigned int Size, LPVOID* Offset);
extern int ScanPageForNonZero(LPVOID Address);

SIZE_T AllocationSize;
PVOID AllocationBase;

PVOID *pAllocationBase;
PSIZE_T pRegionSize;

PGUARDPAGES GuardedPagesToStep;

BOOL AllocationWriteDetected;
BOOL PeImageDetected;
BOOL AllocationDumped;
BOOL AllocationBaseWriteBpSet;
BOOL AllocationBaseExecBpSet;
BOOL EntryPointExecBpSet;
static unsigned int EPBPRegister;

static DWORD_PTR BasePointer, FirstEIP, LastEIP, CurrentEIP, LastDelta, TotalDelta, DeltaMax, LoopDeltaMax;

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

#ifndef _WIN64
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

                if (!AllocationDumped && DumpPEsInRange(AllocationBase, AllocationSize))
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
            
            if (!AllocationDumped && DumpPEsInRange(AllocationBase, AllocationSize))
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
#endif

//            if ((ULONG_PTR)FaultingAddress >= g_our_dll_base && (ULONG_PTR)FaultingAddress < (g_our_dll_base + g_our_dll_size))

//**************************************************************************************
BOOL StepOverGuardPageFault(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
    PGUARDPAGES CurrentGuardPages = GuardedPagesToStep;

    if (LastEIP)
    {
#ifdef _WIN64
        CurrentEIP = ExceptionInfo->ContextRecord->Rip;
#else
        CurrentEIP = ExceptionInfo->ContextRecord->Eip;
#endif
        
        if (CurrentEIP == LastEIP)
        {
            // We want to keep stepping until we're past the instruction
            SetSingleStepMode(ExceptionInfo->ContextRecord, StepOverGuardPageFault);
            return TRUE;
        }
        else
        {   
            if (CurrentGuardPages == NULL)
            {
                DoOutputDebugString("StepOverGuardPageFault error: GuardedPagesToStep not set.\n");
                return FALSE;
            }

            if (ReinstateGuardPages(CurrentGuardPages))
            {
                //DoOutputDebugString("StepOverGuardPageFault: Reinstated page guard.\n");
                GuardedPagesToStep = NULL;
                LastEIP = (DWORD_PTR)NULL;
                CurrentEIP = (DWORD_PTR)NULL;
                return TRUE;
            }

            DoOutputDebugString("StepOverGuardPageFault: Failed to reinstate page guard.\n");
            return FALSE;        
        }
    }
    else
    {
#ifdef _WIN64
        LastEIP = ExceptionInfo->ContextRecord->Rip;
#else
        LastEIP = ExceptionInfo->ContextRecord->Eip;
#endif
        
        if (CurrentGuardPages->LastWriteAddress)
        {
            if (!SystemInfo.dwPageSize)
                GetSystemInfo(&SystemInfo);
            
            // we want to flag writes that occur beyond the first page
            if (ScanPageForNonZero(CurrentGuardPages->LastWriteAddress) && (DWORD_PTR)CurrentGuardPages->LastWriteAddress >= (DWORD_PTR)CurrentGuardPages->BaseAddress + SystemInfo.dwPageSize)
            {
                if (!CurrentGuardPages->WriteDetected)
                {
                    DoOutputDebugString("StepOverGuardPageFault: DEBUG trigger write to 0x%x, base 0x%x, pagesize 0x%x.\n", CurrentGuardPages->LastWriteAddress, CurrentGuardPages->BaseAddress, SystemInfo.dwPageSize);
                    CurrentGuardPages->WriteDetected = TRUE;
                    
                    // we only care about reads that come after writes
                    CurrentGuardPages->ReadDetected = FALSE;
                }
            }
        }
        
        SetSingleStepMode(ExceptionInfo->ContextRecord, StepOverGuardPageFault);
        return TRUE;
    }
}

//**************************************************************************************
BOOL ExtractionGuardPageHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
    DWORD AccessType        = (DWORD)ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
    PVOID AccessAddress     = (PVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
    PVOID FaultingAddress   = (PVOID)ExceptionInfo->ExceptionRecord->ExceptionAddress;
    
    PGUARDPAGES CurrentGuardPages = GetGuardPages(AccessAddress);
    
    if (CurrentGuardPages == NULL)
    {
        DoOutputDebugString("ExtractionGuardPageHandler error: address 0x%x not in guarded pages.\n", AccessAddress);
        return FALSE;
    }
    
    switch (AccessType)
    {
        case EXCEPTION_WRITE_FAULT:
        
            //DoOutputDebugString("ExtractionGuardPageHandler: Write detected at 0x%x by 0x%x\n", AccessAddress, FaultingAddress);

            CurrentGuardPages->LastWriteAddress = AccessAddress;
            
            GuardedPagesToStep = CurrentGuardPages;
            
            SetSingleStepMode(ExceptionInfo->ContextRecord, StepOverGuardPageFault);
            
            break;
            
        case EXCEPTION_READ_FAULT:
        
            if (CurrentGuardPages->WriteDetected)
            {
                if (!(CurrentGuardPages->Protect & (PAGE_EXECUTE_READWRITE || PAGE_EXECUTE_READ || PAGE_EXECUTE)) && !CurrentGuardPages->PagesDumped && !CurrentGuardPages->ReadDetected)
                {
                    DoOutputDebugString("ExtractionGuardPageHandler: Read detected after previous write at 0x%x by 0x%x\n", AccessAddress, FaultingAddress);
                    
                    if (DisableGuardPages(CurrentGuardPages))
                    {
                        CurrentGuardPages->PagesDumped = DumpPEsInRange(CurrentGuardPages->BaseAddress, CurrentGuardPages->RegionSize);
                        if (CurrentGuardPages->PagesDumped)    
                            DoOutputDebugString("ExtractionGuardPageHandler: PE image(s) detected and dumped.\n");
                    }
                    else
                    {
                        DoOutputDebugString("ExtractionGuardPageHandler: Failed to disable guard pages for dump.\n");
                    }
                    
                    // if dumping failed (for example, because of an incomplete image) 
                    // we want to re-enable guard pages so we can try again
                    //if (!CurrentGuardPages->PagesDumped)
                    //{
                    //    ReinstateGuardPages(CurrentGuardPages);
                    //}
                }
            }
            
            CurrentGuardPages->ReadDetected = TRUE;
            CurrentGuardPages->LastReadBy = FaultingAddress;
            
            break;
            
        case EXCEPTION_EXECUTE_FAULT:
        
            DoOutputDebugString("ExtractionGuardPageHandler: Execution detected at 0x%x by 0x%x\n", AccessAddress, FaultingAddress);
            
            if (!(CurrentGuardPages->Protect & (PAGE_EXECUTE_READWRITE || PAGE_EXECUTE_READ || PAGE_EXECUTE)))
            {
                DoOutputDebugString("ExtractionGuardPageHandler: Anomaly detected - pages not marked with execute flag in guarded pages list.\n");                
            }
            
            if (!CurrentGuardPages->PagesDumped)
            {
                DoOutputDebugString("ExtractionGuardPageHandler: Execution within guarded page detected, dumping.\n");
                
                    if (DisableGuardPages(CurrentGuardPages))
                    {
                        CurrentGuardPages->PagesDumped = DumpPEsInRange(CurrentGuardPages->BaseAddress, CurrentGuardPages->RegionSize);
                        if (CurrentGuardPages->PagesDumped)    
                            DoOutputDebugString("ExtractionGuardPageHandler: PE image(s) detected and dumped.\n");
                        else
                        {
                            SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, CurrentGuardPages->BaseAddress);
                            
                            CurrentGuardPages->PagesDumped = DumpMemory(CurrentGuardPages->BaseAddress, CurrentGuardPages->RegionSize);
                            
                            if (CurrentGuardPages->PagesDumped)
                                DoOutputDebugString("ExtractionGuardPageHandler: shellcode detected and dumped.\n");
                            else
                                DoOutputDebugString("ExtractionGuardPageHandler: failed to dump detected shellcode.\n");
                        }
                    }
                else
                {
                    DoOutputDebugString("ExtractionGuardPageHandler: Failed to disable guard pages for dump.\n");
                }
            }
            
            break;
            
        default:
            DoOutputDebugString("ExtractionGuardPageHandler: Unknown access type: 0x%x - error.\n", AccessType);
            return FALSE;
    }
    
    return TRUE;
}

BOOL EntryPointExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	MEMORY_BASIC_INFORMATION meminfo;

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

	DoOutputDebugString("EntryPointExecCallback: Breakpoint %i at Address 0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    memset(&meminfo, 0, sizeof(meminfo));

    if (!VirtualQuery(pBreakpointInfo->Address, &meminfo, sizeof(meminfo)))
    {
        DoOutputErrorString("EntryPointExecCallback: unable to query memory region 0x%x", pBreakpointInfo->Address);
        return FALSE;
    }

    SetCapeMetaData(EXTRACTION_PE, 0, NULL, meminfo.AllocationBase);

    if (AllocationDumped == TRUE)
    {
        DoOutputDebugString("EntryPointExecCallback: allocation already dumped, clearing breakpoint.\n");
        ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);
    }
    else
    {
        AllocationDumped = DumpPEsInRange(meminfo.AllocationBase, meminfo.RegionSize);
        
        if (AllocationDumped)
        {
            DoOutputDebugString("EntryPointExecCallback hook: PE image(s) detected and dumped.\n");
            ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);            
        }
        else
        {
            DoOutputDebugString("EntryPointExecCallback: failed to dump PE module.\n");
            return FALSE;
        }
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

	DoOutputDebugString("EntryPointWriteCallback: Breakpoint %i at Address 0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    if ((DWORD_PTR)pBreakpointInfo->Address < (DWORD_PTR)AllocationBase || (DWORD_PTR)pBreakpointInfo->Address > (DWORD_PTR)AllocationBase + AllocationSize)
    {
        DoOutputDebugString("EntryPointWriteCallback: current AddressOfEntryPoint is not within allocated region. We assume it's only partially written and await further writes.\n");
        return TRUE;        
    }
    
    if (EntryPointExecBpSet == FALSE)
    {
        if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &EPBPRegister, 0, (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address), BP_EXEC, EntryPointExecCallback))
        {
            EntryPointExecBpSet = TRUE;
#ifdef _WIN64
            DoOutputDebugString("EntryPointWriteCallback: Execution bp %d set on EntryPoint 0x%x (RIP = 0x%x).\n", EPBPRegister, (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address), ExceptionInfo->ContextRecord->Rip);
#else
            DoOutputDebugString("EntryPointWriteCallback: Execution bp %d set on EntryPoint 0x%x (EIP = 0x%x).\n", EPBPRegister, (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address), ExceptionInfo->ContextRecord->Eip);
#endif
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
#ifdef _WIN64
            DoOutputDebugString("EntryPointWriteCallback: Updated EntryPoint execution bp %d to 0x%x (RIP = 0x%x).\n", EPBPRegister, (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address), ExceptionInfo->ContextRecord->Rip);
#else
            DoOutputDebugString("EntryPointWriteCallback: Updated EntryPoint execution bp %d to 0x%x (EIP = 0x%x).\n", EPBPRegister, (BYTE*)AllocationBase+*(DWORD*)(pBreakpointInfo->Address), ExceptionInfo->ContextRecord->Eip);
#endif
            
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
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 pNtHeader;
#else
	PIMAGE_NT_HEADERS32 pNtHeader;
#endif    
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

	DoOutputDebugString("PEHeaderWriteCallback: Breakpoint %i at Address 0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    pNtHeader = (PIMAGE_NT_HEADERS)pBreakpointInfo->Address;
    
    if (*(DWORD*)pNtHeader == IMAGE_NT_SIGNATURE)
    {
        PeImageDetected = TRUE;
        
        if (pNtHeader->OptionalHeader.AddressOfEntryPoint && pNtHeader->OptionalHeader.AddressOfEntryPoint < AllocationSize)
        {
            if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 0, (BYTE*)AllocationBase+pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_EXEC, EntryPointExecCallback))
            {
#ifdef _WIN64
                DoOutputDebugString("PEHeaderWriteCallback: Execution bp set on EntryPoint 0x%x (RIP = 0x%x).\n", (DWORD_PTR)AllocationBase+pNtHeader->OptionalHeader.AddressOfEntryPoint, ExceptionInfo->ContextRecord->Rip);
#else
                DoOutputDebugString("PEHeaderWriteCallback: Execution bp set on EntryPoint 0x%x (EIP = 0x%x).\n", (DWORD_PTR)AllocationBase+pNtHeader->OptionalHeader.AddressOfEntryPoint, ExceptionInfo->ContextRecord->Eip);
#endif
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
#ifdef _WIN64
                DoOutputDebugString("PEHeaderWriteCallback: set write bp on AddressOfEntryPoint location (RIP = 0x%x).\n", ExceptionInfo->ContextRecord->Rip);
#else
                DoOutputDebugString("PEHeaderWriteCallback: set write bp on AddressOfEntryPoint location (EIP = 0x%x).\n", ExceptionInfo->ContextRecord->Eip);
#endif
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

	DoOutputDebugString("PEPointerWriteCallback: Breakpoint %i at Address 0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    e_lfanew = *(long*)((pBreakpointInfo->Address));

    if ((unsigned int)e_lfanew > PE_HEADER_LIMIT)
    {
        DoOutputDebugString("PEPointerWriteCallback: pointer to PE header too big: 0x%x (perhaps writing incomplete).\n", e_lfanew);
        return FALSE;
    }

    SetCapeMetaData(EXTRACTION_PE, 0, NULL, AllocationBase);

    if (e_lfanew && (*(DWORD*)((unsigned char*)AllocationBase+e_lfanew) == IMAGE_NT_SIGNATURE))
    {
        if (DumpPEsInRange(AllocationBase, AllocationSize))
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
#ifdef _WIN64
        DoOutputDebugString("PEPointerWriteCallback: set write bp on e_lfanew write location 0x%x (RIP = 0x%x)\n", (BYTE*)AllocationBase + e_lfanew, ExceptionInfo->ContextRecord->Rip);
#else
        DoOutputDebugString("PEPointerWriteCallback: set write bp on e_lfanew write location 0x%x (EIP = 0x%x)\n", (BYTE*)AllocationBase + e_lfanew, ExceptionInfo->ContextRecord->Eip);
#endif
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
	MEMORY_BASIC_INFORMATION meminfo;
    
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

	DoOutputDebugString("MidPageExecCallback: Breakpoint %i at Address 0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    memset(&meminfo, 0, sizeof(meminfo));

    if (!VirtualQuery(pBreakpointInfo->Address, &meminfo, sizeof(meminfo)))
    {
        DoOutputErrorString("MidPageExecCallback: unable to query memory region 0x%x", pBreakpointInfo->Address);
        return FALSE;
    }

    SetCapeMetaData(EXTRACTION_PE, 0, NULL, meminfo.AllocationBase);

    if (!address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address) && (DWORD_PTR)meminfo.BaseAddress > (DWORD_PTR)meminfo.AllocationBase)
    {
        DoOutputDebugString("MidPageExecCallback: Debug: About to scan region for a PE image (base 0x%x, size 0x%x).\n", meminfo.AllocationBase, (DWORD_PTR)meminfo.BaseAddress + meminfo.RegionSize - (DWORD_PTR)meminfo.AllocationBase);
        AllocationDumped = DumpPEsInRange(meminfo.AllocationBase, (DWORD_PTR)meminfo.BaseAddress + meminfo.RegionSize - (DWORD_PTR)meminfo.AllocationBase);
    }
    else if (address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address) || (DWORD_PTR)meminfo.BaseAddress == (DWORD_PTR)meminfo.AllocationBase)
    {
        DoOutputDebugString("MidPageExecCallback: Debug: About to scan region for a PE image (base 0x%x, size 0x%x).\n", meminfo.BaseAddress, meminfo.RegionSize);
        AllocationDumped = DumpPEsInRange(meminfo.BaseAddress, meminfo.RegionSize);
    }
        
    if (AllocationDumped)
    {
        DoOutputDebugString("MidPageExecCallback: PE image(s) detected and dumped.\n");
        ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);
    }
    else
    {
        if (!address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address) && (DWORD_PTR)meminfo.BaseAddress > (DWORD_PTR)meminfo.AllocationBase)
        {
            SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, meminfo.AllocationBase);
            
            AllocationDumped = DumpMemory(meminfo.AllocationBase, (DWORD_PTR)meminfo.BaseAddress + meminfo.RegionSize - (DWORD_PTR)meminfo.AllocationBase);
            
            if (AllocationDumped)
            {
                DoOutputDebugString("MidPageExecCallback: successfully dumped memory range at 0x%x.\n", meminfo.AllocationBase);
                ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);
            }
        }
        else if (address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address) || (DWORD_PTR)meminfo.BaseAddress == (DWORD_PTR)meminfo.AllocationBase)
        {
            SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, meminfo.BaseAddress);
            
            if (ScanForNonZero(meminfo.BaseAddress, meminfo.RegionSize))
                AllocationDumped = DumpMemory(meminfo.BaseAddress, meminfo.RegionSize);
            else 
                DoOutputDebugString("MidPageExecCallback: memory range at 0x%x is empty.\n", meminfo.BaseAddress);
                
            if (AllocationDumped)
            {
                DoOutputDebugString("MidPageExecCallback: successfully dumped memory range at 0x%x.\n", meminfo.BaseAddress);
                ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);
            }
        }
    }
    
    if (!AllocationDumped)
    {
        DoOutputDebugString("MidPageExecCallback: failed to dump memory range at 0x%x.\n", AllocationBase);
        ExtractionClearAll();
    }
	
    DoOutputDebugString("MidPageExecCallback executed successfully.\n");
	
	return TRUE;
}

BOOL ShellcodeExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    MEMORY_BASIC_INFORMATION meminfo;
    //LPVOID PEPointer;
    
    if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("ShellcodeExecCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("ShellcodeExecCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("ShellcodeExecCallback: Breakpoint %i at Address 0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    memset(&meminfo, 0, sizeof(meminfo));

    if (!VirtualQuery(pBreakpointInfo->Address, &meminfo, sizeof(meminfo)))
    {
        DoOutputErrorString("ShellcodeExecCallback: unable to query memory region 0x%x", pBreakpointInfo->Address);
        return FALSE;
    }
    
    DoOutputDebugString("ShellcodeExecCallback: Debug: About to scan region for a PE image (base 0x%x, size 0x%x).\n", meminfo.AllocationBase, meminfo.RegionSize);

    SetCapeMetaData(EXTRACTION_PE, 0, NULL, meminfo.AllocationBase);

    AllocationDumped = DumpPEsInRange(meminfo.AllocationBase, meminfo.RegionSize);
    
    if (AllocationDumped)
    {
        DoOutputDebugString("ShellcodeExecCallback: PE image(s) detected and dumped.\n");
        ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);
    }
    else
    {
        SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, meminfo.AllocationBase);
        
        AllocationDumped = DumpMemory(meminfo.AllocationBase, meminfo.RegionSize);
        
        if (AllocationDumped)
        {
            DoOutputDebugString("ShellcodeExecCallback: successfully dumped memory range at 0x%x.\n", AllocationBase);
            ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);
        }
    }
    
    if (!AllocationDumped)
    {
        DoOutputDebugString("ShellcodeExecCallback: failed to dump memory range at 0x%x.\n", AllocationBase);
        ExtractionClearAll();
    }
	
    DoOutputDebugString("ShellcodeExecCallback executed successfully.\n");
	
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

	DoOutputDebugString("BaseAddressWriteCallback: Breakpoint %i at Address 0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);
    
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
                
                if (DumpPEsInRange(AllocationBase, AllocationSize))
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
#ifdef _WIN64
                    DoOutputDebugString("BaseAddressWriteCallback: set write bp on e_lfanew write location 0x%x (RIP = 0x%x)\n", (BYTE*)pDosHeader + pDosHeader->e_lfanew, ExceptionInfo->ContextRecord->Rip);
#else
                    DoOutputDebugString("BaseAddressWriteCallback: set write bp on e_lfanew write location 0x%x (EIP = 0x%x)\n", (BYTE*)pDosHeader + pDosHeader->e_lfanew, ExceptionInfo->ContextRecord->Eip);
#endif
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
#ifdef _WIN64
            DoOutputDebugString("BaseAddressWriteCallback: set write bp on e_lfanew write location: 0x%x (RIP = 0x%x)\n", (BYTE*)&pDosHeader->e_lfanew, ExceptionInfo->ContextRecord->Rip);
#else
            DoOutputDebugString("BaseAddressWriteCallback: set write bp on e_lfanew write location: 0x%x (EIP = 0x%x)\n", (BYTE*)&pDosHeader->e_lfanew, ExceptionInfo->ContextRecord->Eip);
#endif
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
        DoOutputDebugString("BaseAddressWriteCallback: byte written to 0x%x: 0x%x.\n", pBreakpointInfo->Address, *(BYTE*)pBreakpointInfo->Address);
        
        if (AllocationBaseExecBpSet == TRUE)
        {
            DoOutputDebugString("BaseAddressWriteCallback: allocation exec bp already set, doing nothing.\n");
            return TRUE;
        }
        
        // we add an exec breakpoint on address 0 in case it's shellcode, but leave the write bp in case it's an encrypted PE
        if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, 0, (BYTE*)AllocationBase, BP_EXEC, MidPageExecCallback))
        {
            AllocationBaseExecBpSet = TRUE;
#ifdef _WIN64
            DoOutputDebugString("BaseAddressWriteCallback: Execution breakpoint %d set base address: 0x%x, AllocationBaseExecBpSet = %d (RIP = 0x%x)\n", Register, AllocationBase, AllocationBaseExecBpSet, ExceptionInfo->ContextRecord->Rip);
#else
            DoOutputDebugString("BaseAddressWriteCallback: Execution breakpoint %d set base address: 0x%x, AllocationBaseExecBpSet = %d (EIP = 0x%x)\n", Register, AllocationBase, AllocationBaseExecBpSet, ExceptionInfo->ContextRecord->Eip);
#endif			
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