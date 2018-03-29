/*
CAPE - Config And Payload Extraction
Copyright(C) 2015 - 2018 Context Information Security. (kevin.oreilly@contextis.com)

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
#include "..\hooking.h"
#include <distorm.h>
#include "Debugger.h"
#include "CAPE.h"

#define MAX_INSTRUCTIONS 0x10
#define SINGLE_STEP_LIMIT 0x80
#define CHUNKSIZE 0x10 * MAX_INSTRUCTIONS

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);
extern int DumpModuleInCurrentProcess(LPVOID ModuleBase);
extern int DumpMemory(LPVOID Buffer, SIZE_T Size);

extern DWORD_PTR FileOffsetToVA(DWORD_PTR modBase, DWORD_PTR dwOffset);
BOOL BreakpointSet;
unsigned int DumpCount, Correction, StepCount;
PVOID ModuleBase, DumpAddress;
SIZE_T DumpSize;
BOOL GetSystemTimeAsFileTimeImported, PayloadMarker, PayloadDumped;


BOOL Trace(struct _EXCEPTION_POINTERS* ExceptionInfo)
{

    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DecodedInstructionsCount = 0;

#ifdef _WIN64
    _DecodeType DecodeType = Decode64Bits;
#else
    _DecodeType DecodeType = Decode32Bits;
#endif

    StepCount++;
    
    if (StepCount > SINGLE_STEP_LIMIT)
    {
        DoOutputDebugString("Trace: single-step limit reached, releasing.");
        
        return TRUE;
    }
    
#ifdef _WIN64
    Result = distorm_decode(Offset, (const unsigned char*)ExceptionInfo->ContextRecord->Rip, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount); 
#else
    Result = distorm_decode(Offset, (const unsigned char*)ExceptionInfo->ContextRecord->Eip, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount); 
#endif

    //DoOutputDebugString("%0*I64x ", 8, ExceptionInfo->ContextRecord->Eip);
    //DoOutputDebugString("(%02d) ", DecodedInstruction.size);
    //DoOutputDebugString("%-24s ", (char*)DecodedInstruction.instructionHex.p);
    //DoOutputDebugString("%s", (char*)DecodedInstruction.mnemonic.p);
    //DoOutputDebugString("%s", DecodedInstruction.operands.length != 0 ? " " : "");
    //DoOutputDebugString("%s\n", (char*)DecodedInstruction.operands.p);

    DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);

    SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
    
    return TRUE;
}
    
BOOL BreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("BreakpointCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("BreakpointCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("BreakpointCallback: Breakpoint %i Size=0x%x and Address=0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

    StepCount = 0;

    //ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);    
    
    StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

    SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
    
    return TRUE;
}

BOOL SetInitialBreakpoints(PVOID ImageBase)
{
    DWORD_PTR BreakpointVA;
    DWORD Register;

	if (!bp0 && !bp1 && !bp2 && !bp3)
	{
		DoOutputDebugString("SetInitialBreakpoints: Error - No address specified for Trace breakpoints.\n");
		return FALSE;
	}
    
    if (bp0)
    {
        Register = 0;
        BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)bp0;

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, BP_EXEC, BreakpointCallback))
        {
            DoOutputDebugString("SetInitialBreakpoints: Breakpoint %d set on address 0x%p\n", Register, BreakpointVA);
            BreakpointSet = TRUE;
        }
        else
        {
            DoOutputDebugString("SetInitialBreakpoints: SetBreakpoint failed.\n");
            BreakpointSet = FALSE;
            return FALSE;
        }
    }

    if (bp1)
    {
        Register = 1;
        BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)bp1;

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, BP_EXEC, BreakpointCallback))
        {
            DoOutputDebugString("SetInitialBreakpoints: Breakpoint %d set on address 0x%p\n", Register, BreakpointVA);
            BreakpointSet = TRUE;
        }
        else
        {
            DoOutputDebugString("SetInitialBreakpoints: SetBreakpoint failed.\n");
            BreakpointSet = FALSE;
            return FALSE;
        }
    }

    if (bp2)
    {
        Register = 2;
        BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)bp2;

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, BP_EXEC, BreakpointCallback))
        {
            DoOutputDebugString("SetInitialBreakpoints: Breakpoint %d set on address 0x%p\n", Register, BreakpointVA);
            BreakpointSet = TRUE;
        }
        else
        {
            DoOutputDebugString("SetInitialBreakpoints: SetBreakpoint failed.\n");
            BreakpointSet = FALSE;
            return FALSE;
        }
    }

    if (bp3)
    {
        Register = 3;
        BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)bp3;

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, BP_EXEC, BreakpointCallback))
        {
            DoOutputDebugString("SetInitialBreakpoints: Breakpoint %d set on address 0x%p\n", Register, BreakpointVA);
            BreakpointSet = TRUE;
        }
        else
        {
            DoOutputDebugString("SetInitialBreakpoints: SetBreakpoint failed.\n");
            BreakpointSet = FALSE;
            return FALSE;
        }
    }

    return BreakpointSet;
}
