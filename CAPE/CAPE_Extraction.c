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
#include "..\alloc.h"

#define PE_HEADER_LIMIT 0x200

extern ULONG_PTR g_our_dll_base;
extern DWORD g_our_dll_size;

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

extern unsigned int address_is_in_stack(DWORD Address);

extern BOOL DumpPEsInRange(LPVOID Buffer, SIZE_T Size);
extern int DumpMemory(LPVOID Buffer, unsigned int Size);
extern int ScanForPE(LPVOID Buffer, unsigned int Size, LPVOID* Offset);
extern int ScanPageForNonZero(LPVOID Address);

BOOL ActivateBreakpoints(PTRACKEDPAGES TrackedPages, struct _EXCEPTION_POINTERS* ExceptionInfo);

PTRACKEDPAGES GuardedPagesToStep;
static unsigned int EPBPRegister;
static DWORD_PTR LastEIP, CurrentEIP;

void ExtractionClearAll(PTRACKEDPAGES TrackedPages)
{
    if (!TrackedPages->BaseAddress || !TrackedPages->RegionSize)
    {
        DoOutputDebugString("ExtractionClearAll: Error, BaseAddress or RegionSize zero: 0x%x, 0x%x.\n", TrackedPages->BaseAddress, TrackedPages->RegionSize);
    }    
    
    CapeMetaData->Address = NULL;
    
    DropTrackedPages(TrackedPages);
    
    return;
}

//**************************************************************************************
unsigned int DumpPEsInTrackedPages(PTRACKEDPAGES TrackedPages)
//**************************************************************************************
{
    PTRACKEDPAGES CurrentTrackedPages;
    unsigned int PEsDumped;
    BOOL TrackedPagesFound;
    LPVOID BaseAddress;
    SIZE_T Size;
    
    if (TrackedPages == NULL)
	{
        DoOutputDebugString("DumpPEsInTrackedPages: NULL passed as argument - error.\n");
        return FALSE;
	}    

    if (TrackedPageList == NULL)
    {
        DoOutputDebugString("DumpPEsInTrackedPages: Error - no tracked page list.\n");
        return FALSE;
    }
    
    CurrentTrackedPages = TrackedPageList;

	while (CurrentTrackedPages)
	{
        if (CurrentTrackedPages->BaseAddress == TrackedPages->BaseAddress)
            TrackedPagesFound = TRUE;

        CurrentTrackedPages = TrackedPages->NextTrackedPages;
	}
   
    if (TrackedPagesFound == FALSE)
    {
        DoOutputDebugString("DumpPEsInTrackedPages: failed to locate tracked page(s) in tracked page list.\n");
        return FALSE;
    }

    __try
    {
        BaseAddress = TrackedPages->BaseAddress;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)  
    {  
        DoOutputErrorString("DumpPEsInTrackedPages: Exception trying to access BaseAddress from tracked pages at 0x%x", TrackedPages);
        return FALSE;
    }       
    
    if (!VirtualQuery(TrackedPages->BaseAddress, &TrackedPages->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        DoOutputErrorString("DumpPEsInTrackedPages: unable to query memory region 0x%x", TrackedPages->BaseAddress);
        return FALSE;
    }

    if ((DWORD_PTR)TrackedPages->BaseAddress < (DWORD_PTR)TrackedPages->MemInfo.AllocationBase)
    {
        DoOutputDebugString("DumpPEsInTrackedPages: Anomaly detected - BaseAddress 0x%x below AllocationBase 0x%x.\n", TrackedPages->BaseAddress, TrackedPages->MemInfo.AllocationBase);
        return FALSE;
    }
    
    if ((BYTE*)TrackedPages->BaseAddress + TrackedPages->RegionSize > (BYTE*)TrackedPages->MemInfo.AllocationBase && TrackedPages->MemInfo.RegionSize)
    {
        Size = (BYTE*)TrackedPages->BaseAddress + TrackedPages->RegionSize - (BYTE*)TrackedPages->MemInfo.AllocationBase;
    }
    else
    {
        Size = TrackedPages->RegionSize;
    }
    
    if ((DWORD_PTR)TrackedPages->MemInfo.AllocationBase < (DWORD_PTR)TrackedPages->BaseAddress)
        BaseAddress = TrackedPages->MemInfo.AllocationBase;
    else
        BaseAddress = TrackedPages->BaseAddress;

    PEsDumped = DumpPEsInRange(BaseAddress, Size);
    
    if (PEsDumped)
    {
        DoOutputDebugString("DumpPEsInTrackedPages: Dumped %d PE images from range range 0x%x - 0x%x.\n", PEsDumped, BaseAddress, (BYTE*)BaseAddress + Size);
        TrackedPages->PagesDumped = TRUE;
    }
    else
        DoOutputDebugString("DumpPEsInTrackedPages: No PE images found in range range 0x%x - 0x%x.\n", BaseAddress, (BYTE*)BaseAddress + Size);
    
	return PEsDumped;
}

//**************************************************************************************
void ProcessTrackedPages()
//**************************************************************************************
{
    PTRACKEDPAGES TrackedPages = TrackedPageList;
    
    while (TrackedPages && TrackedPages->BaseAddress && TrackedPages->RegionSize)
    {
        //DoOutputDebugString("ProcessTrackedPages: debug info: Address 0x%x Size 0x%x.\n", TrackedPages->BaseAddress, TrackedPages->RegionSize);
        
        if (TrackedPages->CanDump && !TrackedPages->PagesDumped && ScanForNonZero(TrackedPages->BaseAddress, TrackedPages->RegionSize))
        {
            TrackedPages->PagesDumped = DumpPEsInTrackedPages(TrackedPages);
        
            if (TrackedPages->PagesDumped)
            {
                DoOutputDebugString("ProcessTrackedPages: Found and dumped PE image(s) in range 0x%x - 0x%x.\n", TrackedPages->BaseAddress, (BYTE*)TrackedPages->BaseAddress + TrackedPages->RegionSize);
            }
            else if (TrackedPages->Protect & EXECUTABLE_FLAGS)
            {
                SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedPages->BaseAddress);
                
                TrackedPages->PagesDumped = DumpMemory(TrackedPages->BaseAddress, TrackedPages->RegionSize);
                
                if (TrackedPages->PagesDumped)
                    DoOutputDebugString("ProcessTrackedPages: dumped executable memory range at 0x%x.\n", TrackedPages->BaseAddress);
                else
                    DoOutputDebugString("ProcessTrackedPages: failed to dump executable memory range at 0x%x.\n", TrackedPages->BaseAddress);
            }
        }
        
        TrackedPages = TrackedPages->NextTrackedPages;
    }
}

//**************************************************************************************
void AllocationHandler(PVOID BaseAddress, SIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
//**************************************************************************************
{
    PTRACKEDPAGES TrackedPages = NULL;
    
    if (!BaseAddress || !RegionSize)
    {
        DoOutputDebugString("AllocationHandler: Error, BaseAddress or RegionSize zero: 0x%x, 0x%x.\n", BaseAddress, RegionSize);
        return;    
    }
    
    ProcessTrackedPages();
    
    if (RegionSize < EXTRACTION_MIN_SIZE)
        return;
    
    // Whether we limit tracking to executable regions
    if (!(Protect & EXECUTABLE_FLAGS))
        return;

    DoOutputDebugString("AllocationHandler: BaseAddress:0x%x, RegionSize: 0x%x, Protect: 0x%x.\n", BaseAddress, RegionSize, Protect);
    
    if (TrackedPageList)
        TrackedPages = GetTrackedPages(BaseAddress);
    
    // if memory was previously reserved but not committed
    if (TrackedPages && !TrackedPages->Committed && (AllocationType & MEM_COMMIT))
    {
        DoOutputDebugString("AllocationHandler: Previously reserved, newly committed region at: 0x%x.\n", BaseAddress);
    }   
    else if (TrackedPages && (AllocationType & MEM_RESERVE))
    {
        DoOutputDebugString("AllocationHandler: Re-reserving region at: 0x%x.\n", BaseAddress);
        return;
    }
    else if (TrackedPages)
    {
        // Surely anomolous?!
        DoOutputDebugString("AllocationHandler: Anomaly detected, new allocation already in tracked page list: 0x%x.\n", BaseAddress);
        DoOutputDebugString("AllocationHandler: Debug: TrackedPages->Committed %d AllocationType 0x%x.\n", TrackedPages->Committed, AllocationType);
        return;
    }
    else
        TrackedPages = AddTrackedPages(BaseAddress, RegionSize, Protect);

    if (!TrackedPages)
    {
        DoOutputDebugString("AllocationHandler: Error, unable to locate or add allocation in tracked page list: 0x%x.\n", BaseAddress);
        return;
    }
    
    if (AllocationType & MEM_COMMIT)
    {
        // Allocation committed, we determine whether to guard pages
        TrackedPages->Committed = TRUE;
        
        if (Protect & EXECUTABLE_FLAGS)
        {
            TrackedPages->Guarded = ActivateGuardPages(TrackedPages);
            
            if (TrackedPages->Guarded)
                DoOutputDebugString("AllocationHandler: Guarded newly allocated executable region at 0x%x.\n", BaseAddress);
            else
                DoOutputDebugString("AllocationHandler: Error - failed to guard newly allocated executable region at: 0x%x.\n", BaseAddress);        
        }
        else
            DoOutputDebugString("AllocationHandler: Non-executable region at 0x%x tracked but not guarded.\n", BaseAddress);        
    }
    else
    {   // Allocation not committed, so we can't guard yet
        TrackedPages->Committed = FALSE;
        TrackedPages->Guarded = FALSE;
        DoOutputDebugString("AllocationHandler: Memory reserved but not committed at 0x%x.\n", BaseAddress);
    }
    
    return;
}

//**************************************************************************************
void ProtectionHandler(PVOID Address, SIZE_T RegionSize, ULONG Protect)
//**************************************************************************************
{
    PTRACKEDPAGES TrackedPages = NULL;
    
    if (!Address || !RegionSize)
    {
        DoOutputDebugString("ProtectionHandler: Error, Address or RegionSize zero: 0x%x, 0x%x.\n", Address, RegionSize);
        return;    
    }
    
    ProcessTrackedPages();

    if (RegionSize < EXTRACTION_MIN_SIZE)
        return;
    
    if (!(Protect & EXECUTABLE_FLAGS))
        return;
    
    DoOutputDebugString("ProtectionHandler: Address:0x%x, NumberOfBytesToProtect: 0x%x, NewAccessProtection: 0x%x\n", Address, RegionSize, Protect);

    if (TrackedPageList)
        TrackedPages = GetTrackedPages(Address);
        
    // if region has already been tracked, we update
    if (TrackedPages)
    {
        DoOutputDebugString("ProtectionHandler: Address already in tracked page list: 0x%x.\n", Address);
        
        TrackedPages->RegionSize = RegionSize;
        
        TrackedPages->Protect = Protect;
    }
    else 
        TrackedPages = AddTrackedPages(Address, RegionSize, Protect);

    TrackedPages->ProtectAddress = Address;
    
    if (!TrackedPages)
    {
        DoOutputDebugString("ProtectionHandler: Error, unable to add new region at 0x%x to tracked page list.\n", Address);
        return;
    }
    
    ScanForNonZero(Address, RegionSize);
    
    if (!VirtualQuery(Address, &TrackedPages->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        DoOutputErrorString("ProtectionHandler: unable to query memory region 0x%x", Address);
        return;
    }

    if (Protect != TrackedPages->Protect)
    {
        DoOutputDebugString("ProtectionHandler: updating protection of tracked pages around 0x%x.\n", Address);
        TrackedPages->Protect = Protect;
    }
    
    // deal with newly tracked region
    if (GuardPagesDisabled)
        TrackedPages->BreakpointsSet = ActivateBreakpoints(TrackedPages, NULL);
    else
        TrackedPages->Guarded = ActivateGuardPages(TrackedPages);
    //TrackedPages->Guarded = ActivateGuardPagesOnProtectedRange(TrackedPages);

    if (!TrackedPages->Guarded)
        DoOutputDebugString("ProtectionHandler: Error - unable to activate guard pages around address 0x%x.\n", Address);
        
    return;
}

//**************************************************************************************
void FreeHandler(PVOID BaseAddress)
//**************************************************************************************
{
    PTRACKEDPAGES TrackedPages = GetTrackedPages(BaseAddress);

    if (TrackedPages == NULL)
        return;

    if (!BaseAddress)
    {
        DoOutputDebugString("FreeHandler: Error, BaseAddress zero.\n");
        return;    
    }

    DoOutputDebugString("FreeHandler: Address: 0x%x.\n", BaseAddress);

    if (ScanForNonZero(TrackedPages->BaseAddress, TrackedPages->RegionSize) && !TrackedPages->PagesDumped)
    {
        TrackedPages->PagesDumped = DumpPEsInTrackedPages(TrackedPages);
    
        if (TrackedPages->PagesDumped)
        {
            DoOutputDebugString("FreeHandler: Found and dumped PE image(s) in range 0x%x - 0x%x.\n", TrackedPages->BaseAddress, (BYTE*)TrackedPages->BaseAddress + TrackedPages->RegionSize);
        }
        else if (TrackedPages->Protect & EXECUTABLE_FLAGS)
        {
            SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedPages->BaseAddress);
            
            TrackedPages->PagesDumped = DumpMemory(TrackedPages->BaseAddress, TrackedPages->RegionSize);
            
            if (TrackedPages->PagesDumped)
                DoOutputDebugString("FreeHandler: dumped executable memory range at 0x%x prior to its freeing.\n", TrackedPages->BaseAddress);
            else
                DoOutputDebugString("FreeHandler: failed to dump executable memory range at 0x%x prior to its freeing.\n", TrackedPages->BaseAddress);        
        }
    }
    
    ExtractionClearAll(TrackedPages);
    
    return;
}

//**************************************************************************************
BOOL StepOverGuardPageFault(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
    PTRACKEDPAGES TrackedPages = GuardedPagesToStep;
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
            if (TrackedPages == NULL)
            {
                DoOutputDebugString("StepOverGuardPageFault error: GuardedPagesToStep not set.\n");
                return FALSE;
            }

            LastAccessPage = ((DWORD_PTR)TrackedPages->LastAccessAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;
            ProtectAddressPage = ((DWORD_PTR)TrackedPages->ProtectAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;

            DoOutputDebugString("StepOverGuardPageFault: DEBUG Base 0x%x LastAccess 0x%x by 0x%x (LW 0x%x LR 0x%x).\n", TrackedPages->BaseAddress, TrackedPages->LastAccessAddress, TrackedPages->LastAccessBy, TrackedPages->LastWriteAddress, TrackedPages->LastReadAddress);
            
            if ((DWORD_PTR)TrackedPages->LastAccessAddress >= (DWORD_PTR)TrackedPages->BaseAddress 
                && ((DWORD_PTR)TrackedPages->LastAccessAddress < ((DWORD_PTR)TrackedPages->BaseAddress + SystemInfo.dwPageSize)))
            //  - this page is the first & contains any possible pe header
            {
            
                if (TrackedPages->ProtectAddress && TrackedPages->ProtectAddress > TrackedPages->BaseAddress)
                {
                    if (TrackedPages->LastAccessAddress == TrackedPages->LastWriteAddress && TrackedPages->LastAccessAddress > TrackedPages->ProtectAddress)
                        TrackedPages->WriteCounter++;
                }
                else if (TrackedPages->LastAccessAddress == TrackedPages->LastWriteAddress && TrackedPages->LastAccessAddress > TrackedPages->BaseAddress)
                    TrackedPages->WriteCounter++;

                if (TrackedPages->WriteCounter > SystemInfo.dwPageSize)
                {
                    if (TrackedPages->BreakpointsSet)
                    {
                        DoOutputDebugString("StepOverGuardPageFault: Anomaly detected - switched to breakpoints for initial page, but guard pages still being hit.\n");
                        
                        //DoOutputDebugString("StepOverGuardPageFault: Debug: Last write at 0x%x by 0x%x, last read at 0x%x by 0x%x.\n", TrackedPages->LastWriteAddress, TrackedPages->LastWrittenBy, TrackedPages->LastReadAddress, TrackedPages->LastReadBy);
                        
                        return FALSE;
                    }
                    
                    DoOutputDebugString("StepOverGuardPageFault: Write counter hit limit, switching to breakpoints.\n");
                    
                    if (ActivateBreakpoints(TrackedPages, ExceptionInfo))
                    {
                        //DoOutputDebugString("StepOverGuardPageFault: Switched to breakpoints on first tracked page.\n");
                        
                        //DoOutputDebugString("StepOverGuardPageFault: Debug: Last write at 0x%x by 0x%x, last read at 0x%x by 0x%x.\n", TrackedPages->LastWriteAddress, TrackedPages->LastWrittenBy, TrackedPages->LastReadAddress, TrackedPages->LastReadBy);
                        
                        TrackedPages->BreakpointsSet = TRUE;
                        GuardedPagesToStep = NULL;
                        LastEIP = (DWORD_PTR)NULL;
                        CurrentEIP = (DWORD_PTR)NULL;
                        return TRUE;  
                    }
                    else
                    {
                        DoOutputDebugString("StepOverGuardPageFault: Failed to set breakpoints on first tracked page.\n");
                        return FALSE;  
                    }
                }
                else if (ActivateGuardPages(TrackedPages))
                {
                    //DoOutputDebugString("StepOverGuardPageFault: 0x%x - Reactivated page guard on first tracked page.\n", TrackedPages->LastAccessAddress);
                    
                    GuardedPagesToStep = NULL;
                    LastEIP = (DWORD_PTR)NULL;
                    CurrentEIP = (DWORD_PTR)NULL;
                    return TRUE;  
                }
                else
                {
                    DoOutputDebugString("StepOverGuardPageFault: Failed to activate page guard on first tracked page.\n");
                    return FALSE;  
                }
            } 
            else if (LastAccessPage == ProtectAddressPage)
            {
                if (ActivateGuardPages(TrackedPages))
                {
                    //DoOutputDebugString("StepOverGuardPageFault: 0x%x - Reactivated page guard on page containing protect address.\n", TrackedPages->LastAccessAddress);
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
                if (ActivateSurroundingGuardPages(TrackedPages))
                {
                    //DoOutputDebugString("StepOverGuardPageFault: 0x%x - Reactivated page guard on surrounding pages.\n", TrackedPages->LastAccessAddress);
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

        if (TrackedPages == NULL)
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
    
    PTRACKEDPAGES TrackedPages = GetTrackedPages(AccessAddress);
    
    if (TrackedPages == NULL)
    {
        DoOutputDebugString("ExtractionGuardPageHandler error: address 0x%x not in tracked pages.\n", AccessAddress);
        return FALSE;
    }

    // add check of whether pages *should* be guarded
    // i.e. internal consistency
    
    switch (AccessType)
    {
        case EXCEPTION_WRITE_FAULT:
        
            //DoOutputDebugString("ExtractionGuardPageHandler: Write detected at 0x%x by 0x%x\n", AccessAddress, FaultingAddress);

            TrackedPages->LastAccessAddress = AccessAddress;
            
            TrackedPages->LastAccessBy = FaultingAddress;
            
            TrackedPages->WriteDetected = TRUE;

            TrackedPages->LastWriteAddress = AccessAddress;
            
            TrackedPages->LastWrittenBy = FaultingAddress;

            GuardedPagesToStep = TrackedPages;
            
            SetSingleStepMode(ExceptionInfo->ContextRecord, StepOverGuardPageFault);
            
            break;
            
        case EXCEPTION_READ_FAULT:
        
            TrackedPages->LastAccessAddress = AccessAddress;            
            
            TrackedPages->LastAccessBy = FaultingAddress;
            
            TrackedPages->ReadDetected = TRUE;

            TrackedPages->LastReadAddress = AccessAddress;

            TrackedPages->LastReadBy = FaultingAddress;
            
            GuardedPagesToStep = TrackedPages;
            
            SetSingleStepMode(ExceptionInfo->ContextRecord, StepOverGuardPageFault);
            
            break;
            
        case EXCEPTION_EXECUTE_FAULT:
        
            DoOutputDebugString("ExtractionGuardPageHandler: Execution detected at 0x%x\n", AccessAddress);
            
            if (AccessAddress != FaultingAddress)
            {
                DoOutputDebugString("ExtractionGuardPageHandler: Anomaly detected - AccessAddress != FaultingAddress (0x%x, 0x%x).\n", AccessAddress, FaultingAddress);
            }

            TrackedPages->LastAccessAddress = AccessAddress;            
            
            if (!(TrackedPages->Protect & EXECUTABLE_FLAGS))
            {
                DoOutputDebugString("ExtractionGuardPageHandler: Anomaly detected - pages not marked with execute flag in tracked pages list.\n");                
            }
            
            if (!TrackedPages->PagesDumped)
            {
                DoOutputDebugString("ExtractionGuardPageHandler: Execution within guarded page detected, dumping.\n");
                
                if (DeactivateGuardPages(TrackedPages))
                {
                    //if (DumpPEsInTrackedPages(TrackedPages))
                    //    TrackedPages->PagesDumped = TRUE;
                    
                    if (TrackedPages->PagesDumped)
                        DoOutputDebugString("ExtractionGuardPageHandler: PE image(s) detected and dumped.\n");
                    else
                    {
                        SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedPages->BaseAddress);
                        
                        TrackedPages->PagesDumped = DumpMemory(TrackedPages->BaseAddress, TrackedPages->RegionSize);
                        
                        if (TrackedPages->PagesDumped)
                            DoOutputDebugString("ExtractionGuardPageHandler: shellcode detected and dumped from range 0x%x - 0x%x.\n", TrackedPages->BaseAddress, (BYTE*)TrackedPages->BaseAddress + TrackedPages->RegionSize);
                        else
                            DoOutputDebugString("ExtractionGuardPageHandler: failed to dump detected shellcode from range 0x%x - 0x%x.\n", TrackedPages->BaseAddress, (BYTE*)TrackedPages->BaseAddress + TrackedPages->RegionSize);
                    }
                    
                    ExtractionClearAll(TrackedPages);
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

BOOL PEPointerWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PTRACKEDPAGES TrackedPages;
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

    TrackedPages = GetTrackedPages(pBreakpointInfo->Address);
    
	if (TrackedPages == NULL)
	{
		DoOutputDebugString("PEPointerWriteCallback: unable to locate address 0x%x in tracked pages at 0x%x.\n", pBreakpointInfo->Address, TrackedPages->BaseAddress);
		return FALSE;
	} 

    e_lfanew = *(long*)((pBreakpointInfo->Address));

    if ((unsigned int)e_lfanew > PE_HEADER_LIMIT)
    {
        DoOutputDebugString("PEPointerWriteCallback: pointer to PE header too big: 0x%x (perhaps writing incomplete).\n", e_lfanew);
        return FALSE;
    }

    SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedPages->BaseAddress);

    if (e_lfanew && (*(DWORD*)((unsigned char*)TrackedPages->BaseAddress+e_lfanew) == IMAGE_NT_SIGNATURE))
    {
        if (DumpPEsInTrackedPages(TrackedPages))
        {
            TrackedPages->PagesDumped = TRUE;
            ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);        
            DoOutputDebugString("PEPointerWriteCallback: successfully dumped module.\n");
            return TRUE;
        }
        else
        {
            DoOutputDebugString("PEPointerWriteCallback: failed to dump PE module.\n");
        }
    }
    
//    if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(DWORD), (BYTE*)TrackedPages->BaseAddress+e_lfanew, BP_WRITE, PEHeaderWriteCallback))
//    {
//#ifdef _WIN64
//        DoOutputDebugString("PEPointerWriteCallback: set write bp on e_lfanew write location 0x%x (RIP = 0x%x)\n", (BYTE*)TrackedPages->BaseAddress + e_lfanew, ExceptionInfo->ContextRecord->Rip);
//#else
//        DoOutputDebugString("PEPointerWriteCallback: set write bp on e_lfanew write location 0x%x (EIP = 0x%x)\n", (BYTE*)TrackedPages->BaseAddress + e_lfanew, ExceptionInfo->ContextRecord->Eip);
//#endif
//    }
//    else
//    {
//        DoOutputDebugString("PEPointerWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
//        return FALSE;
//    }

	DoOutputDebugString("PEPointerWriteCallback executed successfully.\n");
	
	return TRUE;
}

BOOL ShellcodeExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{    
    PTRACKEDPAGES TrackedPages;
    
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

    TrackedPages = GetTrackedPages(pBreakpointInfo->Address);
    
	if (TrackedPages == NULL)
	{
		DoOutputDebugString("ShellcodeExecCallback: unable to locate address 0x%x in tracked pages at 0x%x.\n", pBreakpointInfo->Address, TrackedPages->BaseAddress);
		return FALSE;
	}    
    
    if (!VirtualQuery(pBreakpointInfo->Address, &TrackedPages->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        DoOutputErrorString("ShellcodeExecCallback: unable to query memory region 0x%x", pBreakpointInfo->Address);
        return FALSE;
    }

    if (DeactivateGuardPages(TrackedPages))
    {
        SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedPages->MemInfo.AllocationBase);
        
        if (!address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address) && (DWORD_PTR)TrackedPages->MemInfo.BaseAddress > (DWORD_PTR)TrackedPages->MemInfo.AllocationBase)
        {
            DoOutputDebugString("ShellcodeExecCallback: Debug: About to scan region for a PE image (base 0x%x, size 0x%x).\n", TrackedPages->MemInfo.AllocationBase, (DWORD_PTR)TrackedPages->MemInfo.BaseAddress + TrackedPages->MemInfo.RegionSize - (DWORD_PTR)TrackedPages->MemInfo.AllocationBase);
            TrackedPages->PagesDumped = DumpPEsInRange(TrackedPages->MemInfo.AllocationBase, (DWORD_PTR)TrackedPages->MemInfo.BaseAddress + TrackedPages->MemInfo.RegionSize - (DWORD_PTR)TrackedPages->MemInfo.AllocationBase);
        }
        else if (address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address) || (DWORD_PTR)TrackedPages->MemInfo.BaseAddress == (DWORD_PTR)TrackedPages->MemInfo.AllocationBase)
        {
            DoOutputDebugString("ShellcodeExecCallback: Debug: About to scan region for a PE image (base 0x%x, size 0x%x).\n", TrackedPages->MemInfo.BaseAddress, TrackedPages->MemInfo.RegionSize);
            TrackedPages->PagesDumped = DumpPEsInRange(TrackedPages->MemInfo.BaseAddress, TrackedPages->MemInfo.RegionSize);
        }
            
        if (TrackedPages->PagesDumped)
        {
            DoOutputDebugString("ShellcodeExecCallback: PE image(s) detected and dumped.\n");
            ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);
        }
        else
        {
            if (!address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address) && (DWORD_PTR)TrackedPages->MemInfo.BaseAddress > (DWORD_PTR)TrackedPages->MemInfo.AllocationBase)
            {
                SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedPages->MemInfo.AllocationBase);
                
                TrackedPages->PagesDumped = DumpMemory(TrackedPages->MemInfo.AllocationBase, (DWORD_PTR)TrackedPages->MemInfo.BaseAddress + TrackedPages->MemInfo.RegionSize - (DWORD_PTR)TrackedPages->MemInfo.AllocationBase);
                
                if (TrackedPages->PagesDumped)
                {
                    DoOutputDebugString("ShellcodeExecCallback: successfully dumped memory range at 0x%x.\n", TrackedPages->MemInfo.AllocationBase);
                    ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);
                }
            }
            else if (address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address) || (DWORD_PTR)TrackedPages->MemInfo.BaseAddress == (DWORD_PTR)TrackedPages->MemInfo.AllocationBase)
            {
                SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedPages->MemInfo.BaseAddress);
                
                if (ScanForNonZero(TrackedPages->MemInfo.BaseAddress, TrackedPages->MemInfo.RegionSize))
                    TrackedPages->PagesDumped = DumpMemory(TrackedPages->MemInfo.BaseAddress, TrackedPages->MemInfo.RegionSize);
                else 
                    DoOutputDebugString("ShellcodeExecCallback: memory range at 0x%x is empty.\n", TrackedPages->MemInfo.BaseAddress);
                    
                if (TrackedPages->PagesDumped)
                {
                    DoOutputDebugString("ShellcodeExecCallback: successfully dumped memory range at 0x%x.\n", TrackedPages->MemInfo.BaseAddress);
                    ContextClearAllBreakpoints(ExceptionInfo->ContextRecord);
                }
            }
        }
        
        if (!TrackedPages->PagesDumped)
        {
            DoOutputDebugString("ShellcodeExecCallback: Failed to dump memory range at 0x%x.\n", TrackedPages->MemInfo.BaseAddress);
            
            return FALSE;
        }
        else
            DoOutputDebugString("ShellcodeExecCallback executed successfully.\n");
        
        ExtractionClearAll(TrackedPages);
        
        return TRUE;
    }
    else
    {
        DoOutputDebugString("ShellcodeExecCallback: Failed to disable guard pages for dump.\n");
        
        return FALSE;
    }
}

BOOL ActivateBreakpoints(PTRACKEDPAGES TrackedPages, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    DWORD ThreadId;
    unsigned int Register;
    PIMAGE_DOS_HEADER pDosHeader;
    DWORD_PTR LastAccessPage, AddressOfPage;
    
    if (!TrackedPages)
    {
        DoOutputDebugString("ActivateBreakpoints: Error, tracked pages argument NULL.\n");
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
    
    DoOutputDebugString("ActivateBreakpoints: TrackedPages->BaseAddress: 0x%x, TrackedPages->RegionSize: 0x%x, ThreadId: 0x%x\n", TrackedPages->BaseAddress, TrackedPages->RegionSize, ThreadId);
    
    if (TrackedPages->RegionSize == 0 || TrackedPages->BaseAddress == NULL || ThreadId == 0)
    {
        DoOutputDebugString("ActivateBreakpoints: Error, one of the following is NULL: 0x%x, TrackedPages->RegionSize: 0x%x, ThreadId: 0x%x\n", TrackedPages->BaseAddress, TrackedPages->RegionSize, ThreadId);
        return FALSE;
    }
    
    //AddressOfBasePage = ((DWORD_PTR)TrackedPages->BaseAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;
    //ProtectAddressPage = ((DWORD_PTR)TrackedPages->ProtectAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;
 
    if (TrackedPages->ProtectAddress && TrackedPages->ProtectAddress != TrackedPages->BaseAddress)
        CapeMetaData->Address = TrackedPages->ProtectAddress;
    else
        CapeMetaData->Address = TrackedPages->BaseAddress;

    if (ExceptionInfo == NULL)
    {
        if (!SetNextAvailableBreakpoint(GetCurrentThreadId(), &Register, 0, (BYTE*)CapeMetaData->Address, BP_EXEC, ShellcodeExecCallback))
        {
            DoOutputDebugString("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set exec bp on tracked pages base address 0x%x.\n", CapeMetaData->Address);
            return FALSE;
        }
        else
        {
            DoOutputDebugString("ActivateBreakpoints: Set execution breakpoint on protected address: 0x%x\n", CapeMetaData->Address);
        } 
    }
    else
    {    
        if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, 0, (BYTE*)CapeMetaData->Address, BP_EXEC, ShellcodeExecCallback))
        {
            DoOutputDebugString("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set exec bp on tracked pages base address 0x%x.\n", CapeMetaData->Address);
            return FALSE;
        }
        else
        {
            DoOutputDebugString("ActivateBreakpoints: Set execution breakpoint on protected address: 0x%x\n", CapeMetaData->Address);
        } 
    }

    pDosHeader = (PIMAGE_DOS_HEADER)CapeMetaData->Address;
    
    //if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(LONG), (BYTE*)&pDosHeader->e_lfanew, BP_WRITE, PEPointerWriteCallback))
    //{
    //    DoOutputDebugString("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set exec bp on tracked pages base address 0x%x.\n", CapeMetaData->Address);
    //    return FALSE;
    //}
    //else
    //{
    //    DoOutputDebugString("ActivateBreakpoints: Set write breakpoint on e_lfanew address: 0x%x\n", &pDosHeader->e_lfanew);
    //}        

    
    return TRUE;
}
