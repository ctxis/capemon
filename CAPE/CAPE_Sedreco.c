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
extern DWORD_PTR FileOffsetToVA(DWORD_PTR modBase, DWORD_PTR dwOffset);

unsigned int DumpCount, Correction;

BOOL CryptoCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	DWORD StringSize, Offset, Index;
	DWORD_PTR StackPointer, StringAddress;
	
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

	DoOutputDebugString("CryptoCallback: Breakpoint %i Size=0x%x and Address=0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

#ifdef _WIN64
	StackPointer = ExceptionInfo->ContextRecord->Rsp;
#else
	StackPointer = ExceptionInfo->ContextRecord->Esp;
#endif
    
#ifndef _WIN64
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
#else
    if (CAPE_var3)
    {
        StringAddress   = *((DWORD_PTR*)StackPointer+18);
        StringSize      = (DWORD)*((DWORD_PTR*)StackPointer+3);
        Offset          = 0;
        Index           = (DWORD)*((DWORD_PTR*)StackPointer+15);
        
        DoOutputDebugString("RSP: 0x%p, StringAddress: 0x%p, StringSize: 0x%p, Index 0x%x.\n", StackPointer, StringAddress, StringSize, Index);

        StringAddress = (DWORD_PTR)((BYTE*)StringAddress + (unsigned int)Offset);
    }
#endif
    
    CapeMetaData->DumpType = SEDRECO_DATA;
    
    // we use TargetPid from CAPE.h metadata struct for our index value here
#ifdef _WIN64
    // Some newer(?) samples seem to have an offset of 6 in their indices
    if ((unsigned int)Index < Correction)
        Correction = 0;
        
    CapeMetaData->TargetPid = Index - Correction;
#else
    CapeMetaData->TargetPid = Index;
#endif
    
    if (StringSize && DumpCount < 0x10) // never seen more than this in practise
    {
        DumpMemory((LPVOID)StringAddress, (unsigned int)StringSize);
        DumpCount++;
    }
    
    StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
    
    return TRUE;
}

BOOL SetInitialBreakpoint()
{
    DWORD_PTR  BreakpointVA, ModuleBase;
    DWORD Register;
    
    DumpCount = 0;
    Correction = 6;
    
#ifndef _WIN64
	if (CAPE_var1 == NULL && CAPE_var2 == NULL)
#else
	if (CAPE_var3 == NULL)
#endif
	{
		DoOutputDebugString("CAPE error: No address specified for Sedreco encryption function.\n");
		return FALSE;
	}
	else 
    {        
        if (base_of_dll_of_interest == 0)
		{
            ModuleBase = (DWORD_PTR)GetModuleHandle(NULL);
            DoOutputDebugString("DEBUG: About to call FileOffsetToVA with image base 0x%p\n", ModuleBase);
            
#ifndef _WIN64
            if (CAPE_var1)
                BreakpointVA = FileOffsetToVA(ModuleBase, (DWORD_PTR)CAPE_var1);
            else
                BreakpointVA = FileOffsetToVA(ModuleBase, (DWORD_PTR)CAPE_var2);
#else
			BreakpointVA = FileOffsetToVA(ModuleBase, (DWORD_PTR)CAPE_var3);
#endif
		}
        else
        {
            DoOutputDebugString("DEBUG: About to call FileOffsetToVA with base_of_dll_of_interest = 0x%p\n", base_of_dll_of_interest);

#ifndef _WIN64
            if (CAPE_var1)
                BreakpointVA = FileOffsetToVA(base_of_dll_of_interest, (DWORD_PTR)CAPE_var1);
            else
                BreakpointVA = FileOffsetToVA(base_of_dll_of_interest, (DWORD_PTR)CAPE_var2);
#else
			BreakpointVA = FileOffsetToVA(base_of_dll_of_interest, (DWORD_PTR)CAPE_var3);
#endif
        }
        
        DoOutputDebugString("DEBUG: About to call SetNextAvailableBreakpoint with address = 0x%p\n", BreakpointVA);
        
        if (SetNextAvailableBreakpoint(MainThreadId, &Register, 0, (BYTE*)BreakpointVA, BP_EXEC, CryptoCallback))
        {
            DoOutputDebugString("SetInitialBreakpoint: Breakpoint %d set on address 0x%p\n", Register, BreakpointVA);
			return TRUE;
        }
        else
		{
            DoOutputDebugString("SetInitialBreakpoint: SetNextAvailableBreakpoint failed.\n");
			return FALSE;
		}
    }
}
