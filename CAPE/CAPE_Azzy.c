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

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);
extern ULONG_PTR base_of_dll_of_interest;

extern DWORD MainThreadId;
extern int DumpMemory(LPCVOID Buffer, unsigned int Size);
extern int FileOffsetToVA(void* modBase, DWORD_PTR dwOffset);
extern void ShowStack(DWORD StackPointer, unsigned int NumberOfRecords);
extern BOOL StepOverExecutionBreakpoint(PCONTEXT Context, PBREAKPOINTINFO pBreakpointInfo);

BOOL CryptoCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	DWORD StringAddress, StringSize, StackPointer, Offset, Index;

	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("CryptoCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("CryptoCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("CryptoCallback: Breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

	StackPointer = ExceptionInfo->ContextRecord->Esp;
    
    if (CAPE_var1)
    {
        StringSize      = ExceptionInfo->ContextRecord->Edx;
        StringAddress   = ExceptionInfo->ContextRecord->Ecx;
        Offset          = *((DWORD*)StackPointer+1);
        Index           = *((DWORD*)StackPointer+14);
        
        DoOutputDebugString("ESP: 0x%x, StringAddress: 0x%x, StringSize: 0x%x, Index 0x%x.\n", StackPointer, StringAddress, StringSize, Index);

        StringAddress = (DWORD)((BYTE*)StringAddress + (unsigned int)Offset);
    }
    else if (CAPE_var2)
    {
        StringAddress   = *((DWORD*)StackPointer+1);
        StringSize      = *((DWORD*)StackPointer+2);
        Offset          = *((DWORD*)StackPointer+3);
        Index           = *((DWORD*)StackPointer+16);
        
        DoOutputDebugString("ESP: 0x%x, StringAddress: 0x%x, StringSize: 0x%x, Index 0x%x.\n", StackPointer, StringAddress, StringSize, Index);

        StringAddress = (DWORD)((BYTE*)StringAddress + (unsigned int)Offset);
    }
    
    CapeMetaData->DumpType = AZZY_DATA;
    
    // we use TargetPid from CAPE.h metadata struct for our index value here
    CapeMetaData->TargetPid = Index;
    
    if (StringSize)
        DumpMemory((LPVOID)StringAddress, (unsigned int)StringSize);
    
    StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
    
    return TRUE;
}

BOOL SetInitialBreakpoint()
{
    DWORD_PTR  BreakpointVA;
    DWORD ModuleBase, Register;
    
	if (CAPE_var1 == NULL && CAPE_var2 == NULL)
	{
		DoOutputDebugString("CAPE error: No address specified for Azzy encryption function.\n");
		return FALSE;
	}
	else 
    {        
        if (base_of_dll_of_interest == 0)
		{
            ModuleBase = (DWORD)(ULONG_PTR)GetModuleHandle(NULL);
            DoOutputDebugString("DEBUG: About to call FileOffsetToVA with image base 0x%x\n", ModuleBase);
            
            if (CAPE_var1)
                BreakpointVA = FileOffsetToVA((void*)ModuleBase , (DWORD_PTR)CAPE_var1);
            else
                BreakpointVA = FileOffsetToVA((void*)ModuleBase , (DWORD_PTR)CAPE_var2);
		}
        else
        {
            DoOutputDebugString("DEBUG: About to call FileOffsetToVA with base_of_dll_of_interest = 0x%x\n", base_of_dll_of_interest);

            if (CAPE_var1)
                BreakpointVA = FileOffsetToVA((void*)base_of_dll_of_interest, (DWORD_PTR)CAPE_var1);
            else
                BreakpointVA = FileOffsetToVA((void*)base_of_dll_of_interest, (DWORD_PTR)CAPE_var2);
        }
        
        if (SetNextAvailableBreakpoint(MainThreadId, &Register, 0, (BYTE*)BreakpointVA, BP_EXEC, CryptoCallback))
        {
            DoOutputDebugString("SetInitialBreakpoint: Breakpoint %d set on address 0x%x\n", Register, BreakpointVA);
			return TRUE;
        }
        else
		{
            DoOutputDebugString("SetInitialBreakpoint: SetNextAvailableBreakpoint failed.\n");
			return FALSE;
		}
    }
}
