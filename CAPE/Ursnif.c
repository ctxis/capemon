/*
CAPE - Config And Payload Extraction
Copyright(C) 2015 - 2017 Context Information Security. (kevin.oreilly@contextis.com)

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
#include <distorm.h>
#include "Debugger.h"
#include "CAPE.h"

#define MAX_INSTRUCTIONS 32
#define SINGLE_STEP_LIMIT 10

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);
extern int DumpModuleInCurrentProcess(LPVOID ModuleBase);
extern int DumpMemory(LPVOID Buffer, unsigned int Size);

extern DWORD_PTR FileOffsetToVA(DWORD_PTR modBase, DWORD_PTR dwOffset);

unsigned int DumpCount, Correction, StepCount;
PVOID ModuleBase;

//**************************************************************************************
BOOL SingleStepDisassemble(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
    _DecodeResult res;
    _OffsetType offset = 0;
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
        DoOutputDebugString("SingleStepDisassemble: single-step limit reached, dumping module.");
        if (DumpModuleInCurrentProcess(ModuleBase))
            DoOutputDebugString("SingleStepDisassemble: Succssfully dumped module.");
        else
            DoOutputDebugString("SingleStepDisassemble: Module dump failed.");
        
        return TRUE;
    }
    
#ifdef _WIN64
    res = distorm_decode(offset, (const unsigned char*)ExceptionInfo->ContextRecord->Rip, 0x1FB, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount); 
#else
    res = distorm_decode(offset, (const unsigned char*)ExceptionInfo->ContextRecord->Eip, 0x1FB, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount); 
#endif
        
#ifdef _WIN64
    DoOutputDebugString("%0*I64x (%02d) %-24s %s%s%s\n", DecodeType != Decode64Bits ? 8 : 16, ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p); 
#else
    DoOutputDebugString("%0*I64x (%02d) %-24s %s%s%s\n", DecodeType != Decode64Bits ? 8 : 16, ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p); 
#endif
    
    if (!strcmp(DecodedInstruction.mnemonic.p, "CMP"))
    {
#ifdef _WIN64
        if (!strncmp(DecodedInstruction.operands.p, "ECX", 3))
        {
            DoOutputDebugString("SingleStepDisassemble: Comparison detected, RCX = 0x%x, patching.", ExceptionInfo->ContextRecord->Rcx);
            ExceptionInfo->ContextRecord->Rcx = 0;
        }
        else if (!strncmp(DecodedInstruction.operands.p, "R11", 3))
        {
            DoOutputDebugString("SingleStepDisassemble: Comparison detected, R11 = 0x%x, patching.", ExceptionInfo->ContextRecord->R11);
            ExceptionInfo->ContextRecord->R11 = 0;
        }
#else
        DoOutputDebugString("SingleStepDisassemble: Comparison detected, EAX = 0x%x, patching.", ExceptionInfo->ContextRecord->Eax);
        ExceptionInfo->ContextRecord->Eax = 0;
#endif
    }
        
    SetSingleStepMode(ExceptionInfo->ContextRecord, SingleStepDisassemble);
    
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

    StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

    SetSingleStepMode(ExceptionInfo->ContextRecord, SingleStepDisassemble);
    
    return TRUE;
}

BOOL SetInitialBreakpoint()
{
    DWORD_PTR BreakpointVA, FileOffset;
    DWORD Register = 0;
    
	if (CAPE_var1 == NULL)// && CAPE_var2 == NULL)
	{
		DoOutputDebugString("SetInitialBreakpoint: Error - No address specified for Ursnif decryption function.\n");
		return FALSE;
	}

	if (CAPE_var1)
        FileOffset = CAPE_var1;
    //if (CAPE_var2)
    //    FileOffset = CAPE_var2;
    
    DoOutputDebugString("SetInitialBreakpoint: About to call FileOffsetToVA with image base 0x%p and offset 0x%x.\n", ModuleBase, FileOffset);
    
    BreakpointVA = FileOffsetToVA((DWORD_PTR)ModuleBase, (DWORD_PTR)FileOffset);
    
    if (SetBreakpoint(GetCurrentThreadId(), Register, 0, (BYTE*)BreakpointVA, BP_EXEC, BreakpointCallback))
    {
        DoOutputDebugString("SetInitialBreakpoint: Breakpoint %d set on address 0x%p\n", Register, BreakpointVA);
        return TRUE;
    }
    else
    {
        DoOutputDebugString("SetInitialBreakpoint: SetBreakpoint failed.\n");
        return FALSE;
    }
}
