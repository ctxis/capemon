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

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

extern int DumpCurrentProcessFixImports(DWORD NewEP);

DWORD LastEIP, CurrentEIP, EIPDelta, UPX_OEP;

//**************************************************************************************
BOOL SingleStepToOEP(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
    if (LastEIP)
    {
        CurrentEIP = ExceptionInfo->ContextRecord->Eip;
        
        if (CurrentEIP > LastEIP)
            EIPDelta = (unsigned int)(CurrentEIP - LastEIP);
        else
            EIPDelta = (unsigned int)(LastEIP - CurrentEIP);
        
        if (EIPDelta > 0x100)
        {
            UPX_OEP = CurrentEIP;
            DoOutputDebugString("Single-step mode: found OEP = 0x%x, dumping.\n", UPX_OEP);
            DumpCurrentProcessFixImports(UPX_OEP);
        }
        else
        {
            LastEIP = CurrentEIP;
#ifdef _DEBUG            
            DoOutputDebugString("SingleStepToOEP (UPX): EIPDelta = 0x%x\n", EIPDelta);
#endif            
            SetSingleStepMode(ExceptionInfo->ContextRecord, SingleStepToOEP);
        }
        
        return TRUE;
    }
    else
    {
        LastEIP = ExceptionInfo->ContextRecord->Eip;
        DoOutputDebugString("Entering single-step mode until OEP\n");
        SetSingleStepMode(ExceptionInfo->ContextRecord, SingleStepToOEP);
        return TRUE;
    }
}

//**************************************************************************************
BOOL StackReadCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("StackReadCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("StackReadCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("StackReadCallback: Hardware breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

    ContextClearHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);        
    
	// Turn on single-step mode which will dump on OEP (in handler)
    SetSingleStepMode(ExceptionInfo->ContextRecord, SingleStepToOEP);
    
	DoOutputDebugString("StackReadCallback executed successfully.\n");
	
	return TRUE;
}

//**************************************************************************************
BOOL StackWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("StackWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("StackWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("StackWriteCallback: Hardware breakpoint %i Size=0x%x and Address=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);
    
    if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 1, (BYTE*)pBreakpointInfo->Address, BP_READWRITE, StackReadCallback))
    {
        DoOutputDebugString("StackWriteCallback: Updated breakpoint to break on read & write.\n");
    }
    else
	{
        DoOutputDebugString("StackWriteCallback: ContextUpdateCurrentBreakpoint failed.\n");
        return FALSE;
	}

	DoOutputDebugString("StackWriteCallback executed successfully.\n");

	return TRUE;
}
