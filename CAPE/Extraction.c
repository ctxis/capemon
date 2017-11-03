/*
CAPE - Config And Payload Extraction
Copyright(C) 2015 - 2017 Context Information Security. (kevin.oreilly@contextis.com)

This program is free software : you can redistribute it and / or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.
*/
#include <windows.h>
#include "Debugger.h"
#include "CAPE.h"
#include "..\alloc.h"

#define PE_HEADER_LIMIT 0x200

extern ULONG_PTR g_our_dll_base;
extern DWORD g_our_dll_size;

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

extern unsigned int address_is_in_stack(DWORD Address);
extern ULONG_PTR g_our_dll_base;
extern DWORD g_our_dll_size;

extern int operate_on_backtrace(ULONG_PTR _esp, ULONG_PTR _ebp, void *extra, int(*func)(void *, ULONG_PTR));

extern BOOL DumpPEsInRange(LPVOID Buffer, SIZE_T Size);
extern int DumpMemory(LPVOID Buffer, unsigned int Size);
extern int ScanForPE(LPVOID Buffer, unsigned int Size, LPVOID* Offset);
extern int ScanPageForNonZero(LPVOID Address);

BOOL ActivateBreakpoints(PTRACKEDREGION TrackedRegion, struct _EXCEPTION_POINTERS* ExceptionInfo);

PTRACKEDREGION GuardedPagesToStep, TrackedRegionFromHook, CurrentBreakpointRegion;
static DWORD_PTR LastEIP, CurrentEIP;

//**************************************************************************************
BOOL InsideHook(LPVOID* ReturnAddress, LPVOID Address)
//**************************************************************************************
{
    if ((ULONG_PTR)Address >= g_our_dll_base && (ULONG_PTR)Address < (g_our_dll_base + g_our_dll_size))
    {
        if (ReturnAddress)
            *ReturnAddress = Address;
		return TRUE;
    }
	
    return FALSE;
}

//**************************************************************************************
LPVOID GetReturnAddress(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
    LPVOID ReturnAddress = NULL;
    
    __try
    {
#ifdef _WIN64
        operate_on_backtrace(0, (ULONG_PTR)ExceptionInfo->ContextRecord->Rip, &ReturnAddress, InsideHook);
#else
        operate_on_backtrace(0, (ULONG_PTR)ExceptionInfo->ContextRecord->Ebp, &ReturnAddress, InsideHook);
#endif
        
        if (!ReturnAddress)
#ifdef _WIN64
            ReturnAddress = *(LPVOID*)(ExceptionInfo->ContextRecord->Rbp + sizeof(LPVOID));
#else
            ReturnAddress = *(LPVOID*)(ExceptionInfo->ContextRecord->Ebp + sizeof(LPVOID));
#endif
        
        return ReturnAddress;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)  
    {  
#ifdef _WIN64
        DoOutputDebugString("GetReturnAddress: Exception trying to get return address with Rip 0x%p and Rbp 0x%p.\n", ExceptionInfo->ContextRecord->Rip, ExceptionInfo->ContextRecord->Rbp);
#else
        DoOutputDebugString("GetReturnAddress: Exception trying to get return address with base pointer 0x%x.\n", ExceptionInfo->ContextRecord->Ebp);
#endif
        return NULL;
    }
}

//**************************************************************************************
PIMAGE_NT_HEADERS GetNtHeaders(LPVOID BaseAddress)
//**************************************************************************************
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
    
    __try  
    {  
        if (!pDosHeader->e_lfanew) 
        {
            DoOutputDebugString("GetNtHeaders: pointer to PE header zero.\n");
            return NULL;
        }

        if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
        {
            DoOutputDebugString("GetNtHeaders: pointer to PE header too big: 0x%x.\n", pDosHeader->e_lfanew);
            return NULL;
        }

        return (PIMAGE_NT_HEADERS)((BYTE*)BaseAddress + pDosHeader->e_lfanew);
    }  
    __except(EXCEPTION_EXECUTE_HANDLER)  
    {  
        DoOutputDebugString("GetNtHeaders: Exception occured reading around base address 0x%x\n", BaseAddress);
        return NULL;
    }
}

//**************************************************************************************
void ExtractionClearAll(PTRACKEDREGION TrackedRegion)
//**************************************************************************************
{
    if (!TrackedRegion->BaseAddress || !TrackedRegion->RegionSize)
    {
        DoOutputDebugString("ExtractionClearAll: Error, BaseAddress or RegionSize zero: 0x%x, 0x%x.\n", TrackedRegion->BaseAddress, TrackedRegion->RegionSize);
    }    
    
    CapeMetaData->Address = NULL;
    
    DropTrackedRegion(TrackedRegion);
    
    return;
}

//**************************************************************************************
unsigned int DumpPEsInTrackedRegion(PTRACKEDREGION TrackedRegion)
//**************************************************************************************
{
    PTRACKEDREGION CurrentTrackedRegion;
    unsigned int PEsDumped;
    BOOL TrackedRegionFound;
    LPVOID BaseAddress;
    SIZE_T Size;
    
    if (TrackedRegion == NULL)
	{
        DoOutputDebugString("DumpPEsInTrackedRegion: NULL passed as argument - error.\n");
        return FALSE;
	}    

    if (TrackedRegionList == NULL)
    {
        DoOutputDebugString("DumpPEsInTrackedRegion: Error - no tracked region list.\n");
        return FALSE;
    }
    
    CurrentTrackedRegion = TrackedRegionList;

    __try
    {
        while (CurrentTrackedRegion)
        {
            //DEBUG
            //DoOutputDebugString("DumpPEsInTrackedRegion: Debug: CurrentTrackedRegion 0x%p.\n", CurrentTrackedRegion);
            if (CurrentTrackedRegion->BaseAddress == TrackedRegion->BaseAddress)
                TrackedRegionFound = TRUE;

            CurrentTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)  
    {  
        DoOutputErrorString("DumpPEsInTrackedRegion: Exception trying to access BaseAddress from tracked region at 0x%x", TrackedRegion);
        return FALSE;
    }       
   
    if (TrackedRegionFound == FALSE)
    {
        DoOutputDebugString("DumpPEsInTrackedRegion: failed to locate tracked region(s) in tracked region list.\n");
        return FALSE;
    }

    //DEBUG
    //DoOutputDebugString("DumpPEsInTrackedRegion: Found tracked region at 0x%p.\n", CurrentTrackedRegion);

    __try
    {
        BaseAddress = TrackedRegion->BaseAddress;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)  
    {  
        DoOutputErrorString("DumpPEsInTrackedRegion: Exception trying to access BaseAddress from tracked region at 0x%x", TrackedRegion);
        return FALSE;
    }       
    
    //DEBUG
    //DoOutputDebugString("DumpPEsInTrackedRegion: Debug: about to scan for PE image(s).\n");

    if (!VirtualQuery(TrackedRegion->BaseAddress, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        DoOutputErrorString("DumpPEsInTrackedRegion: unable to query memory region 0x%x", TrackedRegion->BaseAddress);
        return FALSE;
    }

    if ((DWORD_PTR)TrackedRegion->BaseAddress < (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase)
    {
        DoOutputDebugString("DumpPEsInTrackedRegion: Anomaly detected - BaseAddress 0x%x below AllocationBase 0x%x.\n", TrackedRegion->BaseAddress, TrackedRegion->MemInfo.AllocationBase);
        return FALSE;
    }
    
    if ((BYTE*)TrackedRegion->BaseAddress + TrackedRegion->RegionSize > (BYTE*)TrackedRegion->MemInfo.AllocationBase && TrackedRegion->MemInfo.RegionSize)
    {
        Size = (BYTE*)TrackedRegion->BaseAddress + TrackedRegion->RegionSize - (BYTE*)TrackedRegion->MemInfo.AllocationBase;
    }
    else
    {
        Size = TrackedRegion->RegionSize;
    }
    
    if ((DWORD_PTR)TrackedRegion->MemInfo.AllocationBase < (DWORD_PTR)TrackedRegion->BaseAddress)
        BaseAddress = TrackedRegion->MemInfo.AllocationBase;
    else
        BaseAddress = TrackedRegion->BaseAddress;

    PEsDumped = DumpPEsInRange(BaseAddress, Size);
    
    if (PEsDumped)
    {
        DoOutputDebugString("DumpPEsInTrackedRegion: Dumped %d PE image(s) from range 0x%x - 0x%x.\n", PEsDumped, BaseAddress, (BYTE*)BaseAddress + Size);
        TrackedRegion->PagesDumped = TRUE;
    }
    else
        DoOutputDebugString("DumpPEsInTrackedRegion: No PE images found in range range 0x%x - 0x%x.\n", BaseAddress, (BYTE*)BaseAddress + Size);
    
	return PEsDumped;
}

//**************************************************************************************
void ProcessTrackedRegion()
//**************************************************************************************
{
    PTRACKEDREGION TrackedRegion = TrackedRegionList;
    
    while (TrackedRegion && TrackedRegion->BaseAddress && TrackedRegion->RegionSize)
    {
        //DoOutputDebugString("ProcessTrackedRegion: debug info: Address 0x%x Size 0x%x.\n", TrackedRegion->BaseAddress, TrackedRegion->RegionSize);
        
        if (TrackedRegion->CanDump && !TrackedRegion->PagesDumped && ScanForNonZero(TrackedRegion->BaseAddress, TrackedRegion->RegionSize))
        {
            TrackedRegion->PagesDumped = DumpPEsInTrackedRegion(TrackedRegion);
        
            if (TrackedRegion->PagesDumped)
            {
                DoOutputDebugString("ProcessTrackedRegion: Found and dumped PE image(s) in range 0x%x - 0x%x.\n", TrackedRegion->BaseAddress, (BYTE*)TrackedRegion->BaseAddress + TrackedRegion->RegionSize);
            }
            else if (TrackedRegion->Protect & EXECUTABLE_FLAGS)
            {
                SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedRegion->BaseAddress);
                
                TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->BaseAddress, TrackedRegion->RegionSize);
                
                if (TrackedRegion->PagesDumped)
                    DoOutputDebugString("ProcessTrackedRegion: dumped executable memory range at 0x%x.\n", TrackedRegion->BaseAddress);
                else
                    DoOutputDebugString("ProcessTrackedRegion: failed to dump executable memory range at 0x%x.\n", TrackedRegion->BaseAddress);
            }
        }
        
        TrackedRegion = TrackedRegion->NextTrackedRegion;
    }
}

//**************************************************************************************
void AllocationHandler(PVOID BaseAddress, SIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
//**************************************************************************************
{
    PTRACKEDREGION TrackedRegion = NULL;
    
    if (!DebuggerInitialised)
        return;

    if (!BaseAddress || !RegionSize)
    {
        DoOutputDebugString("AllocationHandler: Error, BaseAddress or RegionSize zero: 0x%x, 0x%x.\n", BaseAddress, RegionSize);
        return;    
    }
    
    ProcessTrackedRegion();
    
    if (RegionSize < EXTRACTION_MIN_SIZE)
        return;
    
    // Whether we limit tracking to executable regions
    if (!(Protect & EXECUTABLE_FLAGS))
        return;

    DoOutputDebugString("AllocationHandler: BaseAddress:0x%x, RegionSize: 0x%x, Protect: 0x%x.\n", BaseAddress, RegionSize, Protect);
    
    if (TrackedRegionList)
        TrackedRegion = GetTrackedRegion(BaseAddress);
    
    // if memory was previously reserved but not committed
    if (TrackedRegion && !TrackedRegion->Committed && (AllocationType & MEM_COMMIT))
    {
        DoOutputDebugString("AllocationHandler: Previously reserved, newly committed region at: 0x%x.\n", BaseAddress);
    }   
    else if (TrackedRegion && (AllocationType & MEM_RESERVE))
    {
        DoOutputDebugString("AllocationHandler: Re-reserving region at: 0x%x.\n", BaseAddress);
        return;
    }
    else if (TrackedRegion)
    {
        // Surely anomolous?!
        DoOutputDebugString("AllocationHandler: Anomaly detected, new allocation already in tracked region list: 0x%x.\n", BaseAddress);
        DoOutputDebugString("AllocationHandler: Debug: TrackedRegion->Committed %d AllocationType 0x%x.\n", TrackedRegion->Committed, AllocationType);
        return;
    }
    else
        TrackedRegion = AddTrackedRegion(BaseAddress, RegionSize, Protect);

    if (!TrackedRegion)
    {
        DoOutputDebugString("AllocationHandler: Error, unable to locate or add allocation in tracked region list: 0x%x.\n", BaseAddress);
        return;
    }
    
    if (AllocationType & MEM_COMMIT)
    {
        // Allocation committed, we determine whether to guard pages
        TrackedRegion->Committed = TRUE;
        
        if (Protect & EXECUTABLE_FLAGS)
        {
            if (GuardPagesDisabled)
            {
                TrackedRegion->BreakpointsSet = ActivateBreakpoints(TrackedRegion, NULL);
                
                if (TrackedRegion->BreakpointsSet)
                    DoOutputDebugString("AllocationHandler: Breakpoints set on newly-allocated executable region at: 0x%x.\n", BaseAddress);        
                else
                    DoOutputDebugString("AllocationHandler: Error - unable to activate breakpoints around address 0x%x.\n", BaseAddress);        
            }
            else
            {
                TrackedRegion->Guarded = ActivateGuardPages(TrackedRegion);
                //TrackedRegion->Guarded = ActivateGuardPagesOnProtectedRange(TrackedRegion);

                if (TrackedRegion->Guarded)
                    DoOutputDebugString("AllocationHandler: Guarded newly-allocated executable region at 0x%x.\n", BaseAddress);
                else
                    DoOutputDebugString("AllocationHandler: Error - failed to guard newly allocated executable region at: 0x%x.\n", BaseAddress);        
                    
            }
        }
        else
            DoOutputDebugString("AllocationHandler: Non-executable region at 0x%x tracked but not guarded.\n", BaseAddress);        
    }
    else
    {   // Allocation not committed, so we can't set guard pages or breakpoints yet
        TrackedRegion->Committed = FALSE;
        TrackedRegion->Guarded = FALSE;
        DoOutputDebugString("AllocationHandler: Memory reserved but not committed at 0x%x.\n", BaseAddress);
    }
    
    return;
}

//**************************************************************************************
void ProtectionHandler(PVOID Address, SIZE_T RegionSize, ULONG Protect)
//**************************************************************************************
{
    PTRACKEDREGION TrackedRegion = NULL;
    
    if (!DebuggerInitialised)
        return;

    if (!Address || !RegionSize)
    {
        DoOutputDebugString("ProtectionHandler: Error, Address or RegionSize zero: 0x%x, 0x%x.\n", Address, RegionSize);
        return;    
    }
    
    ProcessTrackedRegion();

    if (RegionSize < EXTRACTION_MIN_SIZE)
        return;
    
    if (!(Protect & EXECUTABLE_FLAGS))
        return;
    
    DoOutputDebugString("ProtectionHandler: Address:0x%x, NumberOfBytesToProtect: 0x%x, NewAccessProtection: 0x%x\n", Address, RegionSize, Protect);

    if (TrackedRegionList)
        TrackedRegion = GetTrackedRegion(Address);
        
    // if region has already been tracked, we update
    if (TrackedRegion)
    {
        DoOutputDebugString("ProtectionHandler: Address already in tracked region list: 0x%x.\n", Address);
        
        TrackedRegion->RegionSize = RegionSize;
        
        TrackedRegion->Protect = Protect;
    }
    else 
        TrackedRegion = AddTrackedRegion(Address, RegionSize, Protect);

    TrackedRegion->ProtectAddress = Address;
    
    if (!TrackedRegion)
    {
        DoOutputDebugString("ProtectionHandler: Error, unable to add new region at 0x%x to tracked region list.\n", Address);
        return;
    }
    
    if (!VirtualQuery(Address, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        DoOutputErrorString("ProtectionHandler: unable to query memory region 0x%x", Address);
        return;
    }

    if (Protect != TrackedRegion->Protect)
    {
        DoOutputDebugString("ProtectionHandler: updating protection of tracked region around 0x%x.\n", Address);
        TrackedRegion->Protect = Protect;
    }
    
    // we check if the buffer has already been written to 
    if 
    (
        ScanForNonZero(TrackedRegion->MemInfo.AllocationBase, RegionSize + (BYTE*)Address - (BYTE*)TrackedRegion->MemInfo.AllocationBase) && 
        DumpPEsInRange(TrackedRegion->MemInfo.AllocationBase, RegionSize + (BYTE*)Address - (BYTE*)TrackedRegion->MemInfo.AllocationBase)
    )
    {
        DoOutputDebugString("ProtectionHandler: PE image(s) detected and dumped.\n");
        //ExtractionClearAll();
    }     
    // deal with newly tracked region
    else if (GuardPagesDisabled)
    {
        TrackedRegion->BreakpointsSet = ActivateBreakpoints(TrackedRegion, NULL);
        
        if (TrackedRegion->BreakpointsSet)
            DoOutputDebugString("ProtectionHandler: Breakpoints set on newly-protected executable region at: 0x%x.\n", Address);        
        else
            DoOutputDebugString("ProtectionHandler: Error - unable to activate breakpoints around address 0x%x.\n", Address);        
    }
    else
    {
        TrackedRegion->Guarded = ActivateGuardPages(TrackedRegion);
        //TrackedRegion->Guarded = ActivateGuardPagesOnProtectedRange(TrackedRegion);

        if (TrackedRegion->Guarded)
            DoOutputDebugString("ProtectionHandler: Guarded newly-protected executable region at: 0x%x.\n", Address);        
        else
            DoOutputDebugString("ProtectionHandler: Error - unable to activate guard pages around address 0x%x.\n", Address);
            
    }

    return;
}

//**************************************************************************************
void FreeHandler(PVOID BaseAddress)
//**************************************************************************************
{
    PTRACKEDREGION TrackedRegion = GetTrackedRegion(BaseAddress);

    if (TrackedRegion == NULL)
        return;

    if (!BaseAddress)
    {
        DoOutputDebugString("FreeHandler: Error, BaseAddress zero.\n");
        return;    
    }

    DoOutputDebugString("FreeHandler: Address: 0x%x.\n", BaseAddress);

    if (ScanForNonZero(TrackedRegion->BaseAddress, TrackedRegion->RegionSize) && !TrackedRegion->PagesDumped)
    {
        TrackedRegion->PagesDumped = DumpPEsInTrackedRegion(TrackedRegion);
    
        if (TrackedRegion->PagesDumped)
        {
            DoOutputDebugString("FreeHandler: Found and dumped PE image(s) in range 0x%x - 0x%x.\n", TrackedRegion->BaseAddress, (BYTE*)TrackedRegion->BaseAddress + TrackedRegion->RegionSize);
        }
        else if (TrackedRegion->Protect & EXECUTABLE_FLAGS)
        {
            SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedRegion->BaseAddress);
            
            TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->BaseAddress, TrackedRegion->RegionSize);
            
            if (TrackedRegion->PagesDumped)
                DoOutputDebugString("FreeHandler: dumped executable memory range at 0x%x prior to its freeing.\n", TrackedRegion->BaseAddress);
            else
                DoOutputDebugString("FreeHandler: failed to dump executable memory range at 0x%x prior to its freeing.\n", TrackedRegion->BaseAddress);        
        }
    }
    
    ExtractionClearAll(TrackedRegion);
    
    return;
}

//**************************************************************************************
BOOL StepOverGuardPageFault(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
    PTRACKEDREGION TrackedRegion = GuardedPagesToStep;
    DWORD_PTR LastAccessPage, ProtectAddressPage;
    
    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);
    
    if (!SystemInfo.dwPageSize)
    {
        DoOutputErrorString("StepOverGuardPageFault: Failed to obtain system page size.\n");
        return FALSE;
    }
    
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
            if (TrackedRegion == NULL)
            {
                DoOutputDebugString("StepOverGuardPageFault error: GuardedPagesToStep not set.\n");
                return FALSE;
            }

            LastAccessPage = ((DWORD_PTR)TrackedRegion->LastAccessAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;
            ProtectAddressPage = ((DWORD_PTR)TrackedRegion->ProtectAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;

            //DoOutputDebugString("StepOverGuardPageFault: DEBUG Base 0x%x LastAccess 0x%x by 0x%x (LW 0x%x LR 0x%x).\n", TrackedRegion->BaseAddress, TrackedRegion->LastAccessAddress, TrackedRegion->LastAccessBy, TrackedRegion->LastWriteAddress, TrackedRegion->LastReadAddress);
            
            if ((DWORD_PTR)TrackedRegion->LastAccessAddress >= (DWORD_PTR)TrackedRegion->BaseAddress 
                && ((DWORD_PTR)TrackedRegion->LastAccessAddress < ((DWORD_PTR)TrackedRegion->BaseAddress + SystemInfo.dwPageSize)))
            //  - this page is the first & contains any possible pe header
            {
            
                if (TrackedRegion->ProtectAddress && TrackedRegion->ProtectAddress > TrackedRegion->BaseAddress)
                {
                    if (TrackedRegion->LastAccessAddress == TrackedRegion->LastWriteAddress && TrackedRegion->LastAccessAddress > TrackedRegion->ProtectAddress)
                        TrackedRegion->WriteCounter++;
                }
                else if (TrackedRegion->LastAccessAddress == TrackedRegion->LastWriteAddress && TrackedRegion->LastAccessAddress > TrackedRegion->BaseAddress)
                    TrackedRegion->WriteCounter++;

                if (TrackedRegion->WriteCounter > SystemInfo.dwPageSize)
                {
                    if (TrackedRegion->BreakpointsSet)
                    {
                        DoOutputDebugString("StepOverGuardPageFault: Anomaly detected - switched to breakpoints for initial page, but guard pages still being hit.\n");
                        
                        //DoOutputDebugString("StepOverGuardPageFault: Debug: Last write at 0x%x by 0x%x, last read at 0x%x by 0x%x.\n", TrackedRegion->LastWriteAddress, TrackedRegion->LastWrittenBy, TrackedRegion->LastReadAddress, TrackedRegion->LastReadBy);
                        
                        return FALSE;
                    }
                    
                    DoOutputDebugString("StepOverGuardPageFault: Write counter hit limit, switching to breakpoints.\n");
                    
                    if (ActivateBreakpoints(TrackedRegion, ExceptionInfo))
                    {
                        //DoOutputDebugString("StepOverGuardPageFault: Switched to breakpoints on first tracked region.\n");
                        
                        //DoOutputDebugString("StepOverGuardPageFault: Debug: Last write at 0x%x by 0x%x, last read at 0x%x by 0x%x.\n", TrackedRegion->LastWriteAddress, TrackedRegion->LastWrittenBy, TrackedRegion->LastReadAddress, TrackedRegion->LastReadBy);
                        
                        TrackedRegion->BreakpointsSet = TRUE;
                        GuardedPagesToStep = NULL;
                        LastEIP = (DWORD_PTR)NULL;
                        CurrentEIP = (DWORD_PTR)NULL;
                        return TRUE;  
                    }
                    else
                    {
                        DoOutputDebugString("StepOverGuardPageFault: Failed to set breakpoints on first tracked region.\n");
                        return FALSE;  
                    }
                }
                else if (ActivateGuardPages(TrackedRegion))
                {
                    //DoOutputDebugString("StepOverGuardPageFault: 0x%x - Reactivated page guard on first tracked region.\n", TrackedRegion->LastAccessAddress);
                    
                    GuardedPagesToStep = NULL;
                    LastEIP = (DWORD_PTR)NULL;
                    CurrentEIP = (DWORD_PTR)NULL;
                    return TRUE;  
                }
                else
                {
                    DoOutputDebugString("StepOverGuardPageFault: Failed to activate page guard on first tracked region.\n");
                    return FALSE;  
                }
            } 
            else if (LastAccessPage == ProtectAddressPage)
            {
                if (ActivateGuardPages(TrackedRegion))
                {
                    //DoOutputDebugString("StepOverGuardPageFault: 0x%x - Reactivated page guard on page containing protect address.\n", TrackedRegion->LastAccessAddress);
                    GuardedPagesToStep = NULL;
                    LastEIP = (DWORD_PTR)NULL;
                    CurrentEIP = (DWORD_PTR)NULL;
                    return TRUE;  
                }
                else
                {
                    DoOutputDebugString("StepOverGuardPageFault: Failed to activate page guard on page containing protect address.\n");
                    return FALSE;  
                }
            }
            else
            {
                if (ActivateSurroundingGuardPages(TrackedRegion))
                {
                    //DoOutputDebugString("StepOverGuardPageFault: 0x%x - Reactivated page guard on surrounding pages.\n", TrackedRegion->LastAccessAddress);
                    GuardedPagesToStep = NULL;
                    LastEIP = (DWORD_PTR)NULL;
                    CurrentEIP = (DWORD_PTR)NULL;
                    return TRUE;  
                }
                else
                {
                    DoOutputDebugString("StepOverGuardPageFault: Failed to activate page guard on surrounding pages.\n");
                    return FALSE;  
                }
            }

            DoOutputDebugString("StepOverGuardPageFault: Failed to activate page guards.\n");
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

        if (TrackedRegion == NULL)
        {
            DoOutputDebugString("StepOverGuardPageFault error: GuardedPagesToStep not set.\n");
            return FALSE;
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
    
    PTRACKEDREGION TrackedRegion = GetTrackedRegion(AccessAddress);
    
    if (TrackedRegion == NULL)
    {
        DoOutputDebugString("ExtractionGuardPageHandler error: address 0x%x not in tracked regions.\n", AccessAddress);
        return FALSE;
    }

    // add check of whether pages *should* be guarded
    // i.e. internal consistency
    
    switch (AccessType)
    {
        case EXCEPTION_WRITE_FAULT:
        
            //DoOutputDebugString("ExtractionGuardPageHandler: Write detected at 0x%x by 0x%x\n", AccessAddress, FaultingAddress);

            TrackedRegion->LastAccessAddress = AccessAddress;
            
            TrackedRegion->LastAccessBy = FaultingAddress;
            
            TrackedRegion->WriteDetected = TRUE;

            TrackedRegion->LastWriteAddress = AccessAddress;
            
            TrackedRegion->LastWrittenBy = FaultingAddress;

            GuardedPagesToStep = TrackedRegion;
            
            SetSingleStepMode(ExceptionInfo->ContextRecord, StepOverGuardPageFault);
            
            break;
            
        case EXCEPTION_READ_FAULT:
        
            TrackedRegion->LastAccessAddress = AccessAddress;            
            
            TrackedRegion->LastAccessBy = FaultingAddress;
            
            TrackedRegion->ReadDetected = TRUE;

            TrackedRegion->LastReadAddress = AccessAddress;

            TrackedRegion->LastReadBy = FaultingAddress;
            
            GuardedPagesToStep = TrackedRegion;
            
            SetSingleStepMode(ExceptionInfo->ContextRecord, StepOverGuardPageFault);
            
            break;
            
        case EXCEPTION_EXECUTE_FAULT:
        
            DoOutputDebugString("ExtractionGuardPageHandler: Execution detected at 0x%x\n", AccessAddress);
            
            if (AccessAddress != FaultingAddress)
            {
                DoOutputDebugString("ExtractionGuardPageHandler: Anomaly detected - AccessAddress != FaultingAddress (0x%x, 0x%x).\n", AccessAddress, FaultingAddress);
            }

            TrackedRegion->LastAccessAddress = AccessAddress;            
            
            if (!(TrackedRegion->Protect & EXECUTABLE_FLAGS))
            {
                DoOutputDebugString("ExtractionGuardPageHandler: Anomaly detected - pages not marked with execute flag in tracked region list.\n");                
            }
            
            if (!TrackedRegion->PagesDumped)
            {
                DoOutputDebugString("ExtractionGuardPageHandler: Execution within guarded page detected, dumping.\n");
                
                if (!GuardPagesDisabled && DeactivateGuardPages(TrackedRegion))
                {
                    if (DumpPEsInTrackedRegion(TrackedRegion))
                        TrackedRegion->PagesDumped = TRUE;
                    
                    if (TrackedRegion->PagesDumped)
                        DoOutputDebugString("ExtractionGuardPageHandler: PE image(s) detected and dumped.\n");
                    else
                    {
                        SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedRegion->BaseAddress);
                        
                        TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->BaseAddress, TrackedRegion->RegionSize);
                        
                        if (TrackedRegion->PagesDumped)
                            DoOutputDebugString("ExtractionGuardPageHandler: shellcode detected and dumped from range 0x%x - 0x%x.\n", TrackedRegion->BaseAddress, (BYTE*)TrackedRegion->BaseAddress + TrackedRegion->RegionSize);
                        else
                            DoOutputDebugString("ExtractionGuardPageHandler: failed to dump detected shellcode from range 0x%x - 0x%x.\n", TrackedRegion->BaseAddress, (BYTE*)TrackedRegion->BaseAddress + TrackedRegion->RegionSize);
                    }
                    
                    ExtractionClearAll(TrackedRegion);
                }
                else
                    DoOutputDebugString("ExtractionGuardPageHandler: Failed to disable guard pages for dump.\n");
            }
            
            break;
            
        default:
            DoOutputDebugString("ExtractionGuardPageHandler: Unknown access type: 0x%x - error.\n", AccessType);
            return FALSE;
    }
    
    return TRUE;
}

//**************************************************************************************
BOOL HookReturnCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;

	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("HookReturnCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("HookReturnCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    TrackedRegion = TrackedRegionFromHook;
    TrackedRegionFromHook = NULL;
    
	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("HookReturnCallback: no TrackedRegionFromHook (breakpoint %i at Address 0x%x).\n", pBreakpointInfo->Register, pBreakpointInfo->Address);
		return FALSE;
	} 

	DoOutputDebugString("HookReturnCallback: Breakpoint %i at Address 0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);

    SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedRegion->BaseAddress);

    if (DumpPEsInTrackedRegion(TrackedRegion))
    {
        TrackedRegion->PagesDumped = TRUE;
        ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);        
        DoOutputDebugString("HookReturnCallback: successfully dumped module.\n");
        return TRUE;
    }
    else
    {
        DoOutputDebugString("HookReturnCallback: failed to dump PE module.\n");
        return FALSE;
    }
}

//**************************************************************************************
BOOL OverlayWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;
    LPVOID ReturnAddress;
   
    if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("OverlayWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("OverlayWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);
    
	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("OverlayWriteCallback: unable to locate entry point address 0x%x in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	} 

	DoOutputDebugString("OverlayWriteCallback: Breakpoint %i at Address 0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);
    
    if (!(DWORD*)pBreakpointInfo->Address)
	{
		DoOutputDebugString("OverlayWriteCallback: Zero written, ignoring, leaving breakpoint in place.\n", pBreakpointInfo->Address);
		return TRUE;
	} 
    
    ReturnAddress = GetReturnAddress(ExceptionInfo);    
    
    if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 0, ReturnAddress, BP_EXEC, HookReturnCallback))
    {
        TrackedRegionFromHook = TrackedRegion;
        DoOutputDebugString("OverlayWriteCallback: set exec bp on return address 0x%x.\n", ReturnAddress);
    }
    else
    {
        DoOutputDebugString("OverlayWriteCallback: Failed to set bp on return address 0x%x.\n", ReturnAddress);
    }
	
	return TRUE;
}

//**************************************************************************************
BOOL FinalByteWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;

	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("FinalByteWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("FinalByteWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);
    
	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("FinalByteWriteCallback: unable to locate entry point address 0x%x in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	} 

	DoOutputDebugString("FinalByteWriteCallback: Breakpoint %i at Address 0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);
    
    SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedRegion->BaseAddress);

    if (DumpPEsInTrackedRegion(TrackedRegion))
    {
        TrackedRegion->PagesDumped = TRUE;    
        DoOutputDebugString("FinalByteWriteCallback: successfully dumped module.\n");
        return TRUE;
    }
    else
    {
        DoOutputDebugString("FinalByteWriteCallback: failed to dump PE module.\n");
        return FALSE;
    }
}

//**************************************************************************************
BOOL FinalSectionHeaderWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;
    DWORD VirtualSize;
    PIMAGE_SECTION_HEADER FinalSectionHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    
    if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("FinalSectionHeaderWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("FinalSectionHeaderWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);
    
	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("FinalSectionHeaderWriteCallback: unable to locate entry point address 0x%x in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	} 

	DoOutputDebugString("FinalSectionHeaderWriteCallback: Breakpoint %i at Address 0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    FinalSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD*)pBreakpointInfo->Address - 4);
    
    if (!FinalSectionHeader->VirtualAddress || !FinalSectionHeader->SizeOfRawData)
    {
        DoOutputDebugString("FinalSectionHeaderWriteCallback: current VirtualAddress and FinalSectionHeader->SizeOfRawData not valid: 0x%x, 0x%x (at 0x%x, 0x%x).\n", FinalSectionHeader->VirtualAddress, FinalSectionHeader->SizeOfRawData, (DWORD*)pBreakpointInfo->Address - 1, pBreakpointInfo->Address);
        return TRUE;        
    }
    else
        DoOutputDebugString("FinalSectionHeaderWriteCallback: Section %s VirtualAddress, FinalSectionHeader->Misc.VirtualSize, FinalSectionHeader->SizeOfRawData: 0x%x, 0x%x, 0x%x.\n", FinalSectionHeader->Name, FinalSectionHeader->VirtualAddress, FinalSectionHeader->Misc.VirtualSize, FinalSectionHeader->SizeOfRawData);
    
    ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);
    
    if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, NULL, sizeof(BYTE), (BYTE*)TrackedRegion->BaseAddress + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1, BP_WRITE, FinalByteWriteCallback))
    {
		DoOutputDebugString("FinalSectionHeaderWriteCallback: write bp set on final byte at 0x%x.\n", (BYTE*)TrackedRegion->BaseAddress + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1);
    }
	
    pNtHeader = GetNtHeaders(TrackedRegion->BaseAddress);
    
    if (FinalSectionHeader->Misc.VirtualSize && FinalSectionHeader->Misc.VirtualSize > FinalSectionHeader->SizeOfRawData)
        VirtualSize = FinalSectionHeader->SizeOfRawData;
    else
        VirtualSize = ((FinalSectionHeader->SizeOfRawData / pNtHeader->OptionalHeader.SectionAlignment) + 1) * pNtHeader->OptionalHeader.SectionAlignment;
        
    if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, NULL, sizeof(DWORD), (BYTE*)TrackedRegion->BaseAddress + FinalSectionHeader->VirtualAddress + VirtualSize, BP_WRITE, OverlayWriteCallback))
            DoOutputDebugString("FinalSectionHeaderWriteCallback: Set write breakpoint on final section, last byte: 0x%x\n", (BYTE*)TrackedRegion->BaseAddress + FinalSectionHeader->VirtualAddress + VirtualSize);
    
	return TRUE;
}

//**************************************************************************************
BOOL EntryPointExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;

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

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);
    
	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("EntryPointExecCallback: unable to locate entry point address 0x%x in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	} 

	DoOutputDebugString("EntryPointExecCallback: Breakpoint %i at Address 0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedRegion->BaseAddress);

    if (DumpPEsInTrackedRegion(TrackedRegion))
    {
        TrackedRegion->PagesDumped = TRUE;
        ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);        
        DoOutputDebugString("EntryPointExecCallback: successfully dumped module.\n");
        return TRUE;
    }
    else
    {
        DoOutputDebugString("EntryPointExecCallback: failed to dump PE module.\n");
        return FALSE;
    }
}

//**************************************************************************************
BOOL EntryPointWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;

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

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);
    
	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("EntryPointWriteCallback: unable to locate entry point address 0x%x in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	} 

	DoOutputDebugString("EntryPointWriteCallback: Breakpoint %i at Address 0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    if ((DWORD_PTR)pBreakpointInfo->Address < (DWORD_PTR)TrackedRegion->BaseAddress || (DWORD_PTR)pBreakpointInfo->Address > (DWORD_PTR)TrackedRegion->BaseAddress + TrackedRegion->RegionSize)
    {
        DoOutputDebugString("EntryPointWriteCallback: current AddressOfEntryPoint is not within allocated region. We assume it's only partially written and await further writes.\n");
        return TRUE;        
    }
    
    if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->BaseAddress+*(DWORD*)(pBreakpointInfo->Address), BP_EXEC, EntryPointExecCallback))
    {
        DoOutputDebugString("EntryPointWriteCallback: ContextSetNextAvailableBreakpoint on EntryPoint 0x%x failed\n", (BYTE*)TrackedRegion->BaseAddress+*(DWORD*)(pBreakpointInfo->Address));
        return FALSE;
    }

    DoOutputDebugString("EntryPointWriteCallback: Execution bp %d set on EntryPoint 0x%x.\n", TrackedRegion->ExecBpRegister);
	
	return TRUE;
}

//**************************************************************************************
BOOL MagicWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;
    PIMAGE_DOS_HEADER pDosHeader;
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 pNtHeader;
#else
	PIMAGE_NT_HEADERS32 pNtHeader;
#endif
    DWORD SizeOfHeaders, VirtualSize;
    unsigned int Register;
    
    if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("MagicWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("MagicWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);
    
	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("MagicWriteCallback: unable to locate entry point address 0x%x in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	} 

    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);    
    
    pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->BaseAddress;
    
    if (!pDosHeader->e_lfanew) 
    {
        DoOutputDebugString("MagicWriteCallback: pointer to PE header zero.\n");
        return FALSE;
    }

    if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
    {
        DoOutputDebugString("MagicWriteCallback: pointer to PE header too big: 0x%x.\n", pDosHeader->e_lfanew);
        return FALSE;
    }

	DoOutputDebugString("MagicWriteCallback: Breakpoint %i at Address 0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)TrackedRegion->BaseAddress + pDosHeader->e_lfanew);
    
    if ((pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
    {
        DoOutputDebugString("MagicWriteCallback: Magic value not valid NT: 0x%x (@0x%x).\n", pNtHeader->OptionalHeader.Magic, &pNtHeader->OptionalHeader.Magic);
        return TRUE;
    }
    
    if (pNtHeader->OptionalHeader.AddressOfEntryPoint > TrackedRegion->RegionSize)
    {
        DoOutputDebugString("MagicWriteCallback: AddressOfEntryPoint invalid: 0x%x.\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
        return TRUE;
    }
    
    if (*(BYTE*)TrackedRegion->BaseAddress + pNtHeader->OptionalHeader.AddressOfEntryPoint)
    {
        ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);        

        if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->BaseAddress + pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_EXEC, EntryPointExecCallback))
        {
            DoOutputDebugString("MagicWriteCallback: ContextSetNextAvailableBreakpoint on EntryPoint 0x%x failed\n", (BYTE*)TrackedRegion->BaseAddress+*(DWORD*)(pBreakpointInfo->Address));
            return FALSE;
        }

        DoOutputDebugString("MagicWriteCallback: Execution bp %d set on EntryPoint 0x%x.\n", TrackedRegion->ExecBp);
    }
    else
    {
        if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(BYTE), (BYTE*)TrackedRegion->BaseAddress + pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_WRITE, EntryPointWriteCallback))
        {
            DoOutputDebugString("MagicWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
            ContextClearBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);        
            return FALSE;
        }
        
        DoOutputDebugString("MagicWriteCallback: set write bp on AddressOfEntryPoint location 0x%x.\n", (BYTE*)TrackedRegion->BaseAddress + pNtHeader->OptionalHeader.AddressOfEntryPoint);
    }
    
    SizeOfHeaders = pDosHeader->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader;

    if (pNtHeader->FileHeader.NumberOfSections && pNtHeader->FileHeader.SizeOfOptionalHeader)    
    {
        PIMAGE_SECTION_HEADER FinalSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)TrackedRegion->BaseAddress + SizeOfHeaders + (sizeof(IMAGE_SECTION_HEADER) * (pNtHeader->FileHeader.NumberOfSections - 1)));
        
        DoOutputDebugString("MagicWriteCallback: DEBUG: NumberOfSections %d, SizeOfHeaders 0x%x.\n", pNtHeader->FileHeader.NumberOfSections, SizeOfHeaders);

        if (FinalSectionHeader->VirtualAddress && FinalSectionHeader->SizeOfRawData)
        {
            if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(BYTE), (BYTE*)TrackedRegion->BaseAddress + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1, BP_WRITE, FinalByteWriteCallback))
            {
                DoOutputDebugString("MagicWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%x.\n", (BYTE*)TrackedRegion->BaseAddress + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1);
                return FALSE;
            }

            DoOutputDebugString("MagicWriteCallback: Set write breakpoint on final section, last byte: 0x%x\n", (BYTE*)TrackedRegion->BaseAddress + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData);
            
            if (FinalSectionHeader->Misc.VirtualSize && FinalSectionHeader->Misc.VirtualSize > FinalSectionHeader->SizeOfRawData)
                VirtualSize = FinalSectionHeader->Misc.VirtualSize;
            else if (pNtHeader->OptionalHeader.SectionAlignment)
                VirtualSize = ((FinalSectionHeader->SizeOfRawData / pNtHeader->OptionalHeader.SectionAlignment) + 1) * pNtHeader->OptionalHeader.SectionAlignment;
            else
                VirtualSize = ((FinalSectionHeader->SizeOfRawData / SystemInfo.dwPageSize) + 1) * SystemInfo.dwPageSize;
            
            if (FinalSectionHeader->VirtualAddress)
            {
                if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, NULL, sizeof(DWORD), (BYTE*)TrackedRegion->BaseAddress + FinalSectionHeader->VirtualAddress + VirtualSize, BP_WRITE, OverlayWriteCallback))
                {
                    DoOutputDebugString("MagicWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%x.\n", (BYTE*)TrackedRegion->BaseAddress + FinalSectionHeader->VirtualAddress + FinalSectionHeader->Misc.VirtualSize);
                    return FALSE;
                }

                DoOutputDebugString("MagicWriteCallback: Set write breakpoint on final section, last byte: 0x%x\n", (BYTE*)TrackedRegion->BaseAddress + FinalSectionHeader->VirtualAddress + FinalSectionHeader->Misc.VirtualSize);
            }
        }
        else
        {
            if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(DWORD), &FinalSectionHeader->SizeOfRawData, BP_WRITE, FinalSectionHeaderWriteCallback))
            {
                DoOutputDebugString("MagicWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%x.\n", &FinalSectionHeader->SizeOfRawData);
                return FALSE;
            }

            DoOutputDebugString("MagicWriteCallback: Set write breakpoint on final section header (SizeOfRawData: 0x%x)\n", &FinalSectionHeader->SizeOfRawData);
        }        
    }
    
    DoOutputDebugString("MagicWriteCallback executed successfully.\n");
	
	return TRUE;
}

//**************************************************************************************
BOOL PEPointerWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;
    PIMAGE_DOS_HEADER pDosHeader;
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 pNtHeader;
#else
	PIMAGE_NT_HEADERS32 pNtHeader;
#endif    
    LPVOID ReturnAddress;

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

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);
    
	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("PEPointerWriteCallback: unable to locate address 0x%x in tracked region at 0x%x.\n", pBreakpointInfo->Address, TrackedRegion->BaseAddress);
		return FALSE;
	} 

    ReturnAddress = GetReturnAddress(ExceptionInfo);
    
    //if (ReturnAddress && InsideHook(NULL, ReturnAddress))
    if (ReturnAddress)
    {
		DoOutputDebugString("PEPointerWriteCallback: We are in a hooked function with return address 0x%p.\n", ReturnAddress);
    
        if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 0, ReturnAddress, BP_EXEC, HookReturnCallback))
        {
            TrackedRegionFromHook = TrackedRegion;
            DoOutputDebugString("PEPointerWriteCallback: set exec bp on return address 0x%x.\n", ReturnAddress);
        }
        else
        {
            DoOutputDebugString("PEPointerWriteCallback: Failed to set bp on return address 0x%x.\n", ReturnAddress);
        }
	}

    pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->BaseAddress;
    
    if (!pDosHeader->e_lfanew) 
    {
        DoOutputDebugString("PEPointerWriteCallback: candidate pointer to PE header zero.\n");
        return FALSE;
    }

    if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
    {
        DoOutputDebugString("PEPointerWriteCallback: candidate pointer to PE header too big: 0x%x.\n", pDosHeader->e_lfanew);
        return FALSE;
    }

    SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedRegion->BaseAddress);

    if (pDosHeader->e_lfanew && IsDisguisedPEHeader(TrackedRegion->BaseAddress))
    {
        if (DumpPEsInTrackedRegion(TrackedRegion))
        {
            TrackedRegion->PagesDumped = TRUE;
            ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);        
            DoOutputDebugString("PEPointerWriteCallback: successfully dumped module.\n");
            return TRUE;
        }
        else
        {
            DoOutputDebugString("PEPointerWriteCallback: failed to dump PE module.\n");
        }
    }

    pNtHeader = (PIMAGE_NT_HEADERS32)((BYTE*)TrackedRegion->BaseAddress + pDosHeader->e_lfanew);

    if ((pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) || (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC))
    {
        if (IsDisguisedPEHeader(TrackedRegion->BaseAddress))
        {
            if (DumpPEsInTrackedRegion(TrackedRegion))
            {
                TrackedRegion->PagesDumped = TRUE;
                ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);        
                DoOutputDebugString("PEPointerWriteCallback: successfully dumped module.\n");
                return TRUE;
            }
            else
            {
                DoOutputDebugString("PEPointerWriteCallback: failed to dump PE module.\n");
            }
        }
    }

    if (TrackedRegion->MagicBp)
    {
        if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->MagicBpRegister, sizeof(WORD), &pNtHeader->OptionalHeader.Magic, BP_WRITE, MagicWriteCallback))
        {
            DoOutputDebugString("PEPointerWriteCallback: Failed to set breakpoint on magic address.\n");
            return FALSE;
        }
    }
    else if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &TrackedRegion->MagicBpRegister, sizeof(WORD), &pNtHeader->OptionalHeader.Magic, BP_WRITE, MagicWriteCallback))
    {
        DoOutputDebugString("PEPointerWriteCallback: Failed to set breakpoint on magic address.\n");
        return FALSE;
    }
    
    TrackedRegion->MagicBp = &pNtHeader->OptionalHeader.Magic;

	DoOutputDebugString("PEPointerWriteCallback executed successfully with a breakpoint on magic address.\n");
	
	return TRUE;
}

//**************************************************************************************
BOOL ShellcodeExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{    
    PTRACKEDREGION TrackedRegion;
    
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

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);
    
	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("ShellcodeExecCallback: unable to locate address 0x%x in tracked region at 0x%x.\n", pBreakpointInfo->Address, TrackedRegion->BaseAddress);
		return FALSE;
	}    
    
    if (!VirtualQuery(pBreakpointInfo->Address, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        DoOutputErrorString("ShellcodeExecCallback: unable to query memory region 0x%x", pBreakpointInfo->Address);
        return FALSE;
    }

    if (GuardPagesDisabled)
    {
        SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedRegion->MemInfo.AllocationBase);

        DoOutputDebugString("ShellcodeExecCallback: Debug: About to scan region for a PE image (base 0x%x, size 0x%x).\n", TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);
        
        TrackedRegion->PagesDumped = DumpPEsInRange(TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);

        if (TrackedRegion->PagesDumped)
        {
            DoOutputDebugString("ShellcodeExecCallback: PE image(s) detected and dumped.\n");
            ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);
            
        }
        else
        {
            SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedRegion->MemInfo.AllocationBase);
            
            TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);
            
            if (TrackedRegion->PagesDumped)
            {
                DoOutputDebugString("ShellcodeExecCallback: successfully dumped memory range at 0x%x.\n", TrackedRegion->MemInfo.AllocationBase);
                ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);
            }
        }
        
        return TRUE;
    }

    if (!GuardPagesDisabled && DeactivateGuardPages(TrackedRegion))
    {
        SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedRegion->MemInfo.AllocationBase);
        
        if (!address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address) && (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress > (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase)
        {
            DoOutputDebugString("ShellcodeExecCallback: Debug: About to scan region for a PE image (base 0x%x, size 0x%x).\n", TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);
            TrackedRegion->PagesDumped = DumpPEsInRange(TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);
        }
        else if (address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address) || (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress == (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase)
        {
            DoOutputDebugString("ShellcodeExecCallback: Debug: About to scan region for a PE image (base 0x%x, size 0x%x).\n", TrackedRegion->MemInfo.BaseAddress, TrackedRegion->MemInfo.RegionSize);
            TrackedRegion->PagesDumped = DumpPEsInRange(TrackedRegion->MemInfo.BaseAddress, TrackedRegion->MemInfo.RegionSize);
        }
            
        if (TrackedRegion->PagesDumped)
        {
            DoOutputDebugString("ShellcodeExecCallback: PE image(s) detected and dumped.\n");
            ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);
        }
        else
        {
            if (!address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address) && (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress > (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase)
            {
                SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedRegion->MemInfo.AllocationBase);
                
                TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);
                
                if (TrackedRegion->PagesDumped)
                {
                    DoOutputDebugString("ShellcodeExecCallback: successfully dumped memory range at 0x%x.\n", TrackedRegion->MemInfo.AllocationBase);
                    ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);
                }
            }
            else if (address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address) || (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress == (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase)
            {
                SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedRegion->MemInfo.BaseAddress);
                
                if (ScanForNonZero(TrackedRegion->MemInfo.BaseAddress, TrackedRegion->MemInfo.RegionSize))
                    TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->MemInfo.BaseAddress, TrackedRegion->MemInfo.RegionSize);
                else 
                    DoOutputDebugString("ShellcodeExecCallback: memory range at 0x%x is empty.\n", TrackedRegion->MemInfo.BaseAddress);
                    
                if (TrackedRegion->PagesDumped)
                {
                    DoOutputDebugString("ShellcodeExecCallback: successfully dumped memory range at 0x%x.\n", TrackedRegion->MemInfo.BaseAddress);
                    ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);
                }
            }
        }
        
        if (!TrackedRegion->PagesDumped)
        {
            DoOutputDebugString("ShellcodeExecCallback: Failed to dump memory range at 0x%x.\n", TrackedRegion->MemInfo.BaseAddress);
            
            return FALSE;
        }
        else
            DoOutputDebugString("ShellcodeExecCallback executed successfully.\n");
        
        ExtractionClearAll(TrackedRegion);
        
        return TRUE;
    }
    else
    {
        DoOutputDebugString("ShellcodeExecCallback: Failed to disable guard pages for dump.\n");
        
        return FALSE;
    }
}

//**************************************************************************************
BOOL ActivateBreakpoints(PTRACKEDREGION TrackedRegion, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
    DWORD ThreadId;
    unsigned int Register;
    PIMAGE_DOS_HEADER pDosHeader;
    //DWORD_PTR LastAccessPage, AddressOfPage;
    
    if (!TrackedRegion)
    {
        DoOutputDebugString("ActivateBreakpoints: Error, tracked region argument NULL.\n");
        return FALSE;
    }

    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);
    
    if (!SystemInfo.dwPageSize)
    {
        DoOutputErrorString("ActivateBreakpoints: Failed to obtain system page size.\n");
        return FALSE;
    }
    
    ThreadId = GetCurrentThreadId();
    
    DoOutputDebugString("ActivateBreakpoints: TrackedRegion->BaseAddress: 0x%x, TrackedRegion->RegionSize: 0x%x, ThreadId: 0x%x\n", TrackedRegion->BaseAddress, TrackedRegion->RegionSize, ThreadId);
    
    if (TrackedRegion->RegionSize == 0 || TrackedRegion->BaseAddress == NULL || ThreadId == 0)
    {
        DoOutputDebugString("ActivateBreakpoints: Error, one of the following is NULL: 0x%x, TrackedRegion->RegionSize: 0x%x, ThreadId: 0x%x\n", TrackedRegion->BaseAddress, TrackedRegion->RegionSize, ThreadId);
        return FALSE;
    }
    
    //AddressOfBasePage = ((DWORD_PTR)TrackedRegion->BaseAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;
    //ProtectAddressPage = ((DWORD_PTR)TrackedRegion->ProtectAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;
 
    if (CurrentBreakpointRegion && TrackedRegion != CurrentBreakpointRegion)
    {
        DoOutputDebugString("ActivateBreakpoints: Switching breakpoints from region 0x%p to 0x%p.\n", CurrentBreakpointRegion->BaseAddress, TrackedRegion->BaseAddress);
        
        CurrentBreakpointRegion->TrackedRegionBreakpoints = GetThreadBreakpoints(GetCurrentThreadId());

        ClearAllBreakpoints();
        
        CurrentBreakpointRegion = TrackedRegion;
        
        if (CurrentBreakpointRegion->BreakpointsSet && CurrentBreakpointRegion->TrackedRegionBreakpoints)
        {
            if (!SetThreadBreakpoints(CurrentBreakpointRegion->TrackedRegionBreakpoints))
            {
                DoOutputDebugString("ActivateBreakpoints: Failed to restore region breakpoints for region at 0x%p.\n", CurrentBreakpointRegion->BaseAddress);
                return FALSE;
            }
            
            DoOutputDebugString("ActivateBreakpoints: Restored region breakpoints for region at 0x%p.\n", CurrentBreakpointRegion->BaseAddress);
            
            return TRUE;
        }
    }
    
    if (TrackedRegion->BreakpointsSet && TrackedRegion->ExecBp && TrackedRegion->ProtectAddress == TrackedRegion->ExecBp)
    {
        DoOutputDebugString("ActivateBreakpoints: Current tracked region already has breakpoints set.\n");
        return TRUE;    
    }
    
    if (TrackedRegion->ProtectAddress && TrackedRegion->ProtectAddress != TrackedRegion->BaseAddress)
        TrackedRegion->ExecBp = TrackedRegion->ProtectAddress;
    else
        TrackedRegion->ExecBp = TrackedRegion->BaseAddress;

    CapeMetaData->Address = TrackedRegion->ExecBp;
    
    if (ExceptionInfo == NULL)
    {
        if (!SetNextAvailableBreakpoint(GetCurrentThreadId(), &TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->ExecBp, BP_EXEC, ShellcodeExecCallback))
        {
            DoOutputDebugString("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set exec bp on tracked region protect address 0x%x.\n", TrackedRegion->ExecBp);
            return FALSE;
        }

        DoOutputDebugString("ActivateBreakpoints: Set execution breakpoint on protected address: 0x%x\n", TrackedRegion->ExecBp);
    }
    else
    {    
        if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->ExecBp, BP_EXEC, ShellcodeExecCallback))
        {
            DoOutputDebugString("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set exec bp on tracked region protect address 0x%x.\n", TrackedRegion->ExecBp);
            return FALSE;
        }

        DoOutputDebugString("ActivateBreakpoints: Set execution breakpoint on protected address: 0x%x\n", TrackedRegion->ExecBp);
    }

    pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->ExecBp;
    
    if (ExceptionInfo == NULL)
    {
        if (!SetNextAvailableBreakpoint(GetCurrentThreadId(), &Register, sizeof(LONG), (BYTE*)&pDosHeader->e_lfanew, BP_WRITE, PEPointerWriteCallback))
        {
            DoOutputDebugString("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set exec bp on tracked region protect address 0x%x.\n", TrackedRegion->ExecBp);
            return FALSE;
        }

        DoOutputDebugString("ActivateBreakpoints: Set execution breakpoint on protected address: 0x%x\n", TrackedRegion->ExecBp);
    }
    else
    {    
        if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(LONG), (BYTE*)&pDosHeader->e_lfanew, BP_WRITE, PEPointerWriteCallback))
        {
            DoOutputDebugString("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set exec bp on tracked region protect address 0x%x.\n", TrackedRegion->ExecBp);
            return FALSE;
        }

        DoOutputDebugString("ActivateBreakpoints: Set write breakpoint on e_lfanew address: 0x%x\n", &pDosHeader->e_lfanew);
    }

    CurrentBreakpointRegion = TrackedRegion;
    
    return TRUE;
}
