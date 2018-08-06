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
#include <distorm.h>
#include "..\hooking.h"
#include "Debugger.h"
#include "CAPE.h"

#define MAX_INSTRUCTIONS 0x10
#define SINGLE_STEP_LIMIT 0x80  // default unless specified in web ui
#define CHUNKSIZE 0x10 * MAX_INSTRUCTIONS

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);
extern int DumpModuleInCurrentProcess(LPVOID ModuleBase);
extern int DumpMemory(LPVOID Buffer, SIZE_T Size);
extern char *convert_address_to_dll_name_and_offset(ULONG_PTR addr, unsigned int *offset);
extern DWORD_PTR FileOffsetToVA(DWORD_PTR modBase, DWORD_PTR dwOffset);
extern BOOL ScyllaGetSectionByName(PVOID ImageBase, char* Name, PVOID* SectionData, SIZE_T* SectionSize);

BOOL BreakpointSet, DllPrinted;
PVOID ModuleBase, DumpAddress;
SIZE_T DumpSize;
BOOL GetSystemTimeAsFileTimeImported, PayloadMarker, PayloadDumped;
unsigned int DumpCount, Correction, StepCount, StepLimit;
int StepOverRegister, TraceDepthCount, TraceDepthLimit;

BOOL Trace(struct _EXCEPTION_POINTERS* ExceptionInfo);
BOOL BreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo);

BOOL DoSetSingleStepMode(int Register, PCONTEXT Context, PVOID Handler)
{
    StepOverRegister = Register;
    return SetSingleStepMode(Context, Trace);
}

BOOL Trace(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID ReturnAddress;
    char* DllName;
    unsigned int DllRVA;

    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DecodedInstructionsCount = 0;

    StepCount++;
    
    if (StepCount > StepLimit)
    {
        DoOutputDebugString("Trace: single-step limit reached (%d), releasing.", StepLimit);
        return TRUE;
    }
    
#ifdef _WIN64
    DllName = convert_address_to_dll_name_and_offset((ULONG_PTR)ExceptionInfo->ContextRecord->Rip, &DllRVA);
    _DecodeType DecodeType = Decode64Bits;
    Result = distorm_decode(Offset, (const unsigned char*)ExceptionInfo->ContextRecord->Rip, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount); 
    DoOutputDebugString("0x%p (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#else
    DllName = convert_address_to_dll_name_and_offset((ULONG_PTR)ExceptionInfo->ContextRecord->Eip, &DllRVA);
    _DecodeType DecodeType = Decode32Bits;
    Result = distorm_decode(Offset, (const unsigned char*)ExceptionInfo->ContextRecord->Eip, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount); 
    DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#endif

    if (!DllPrinted && DllName)
    {
        DoOutputDebugString("Trace: Tracing in %s (RVA 0x%x).\n", DllName, DllRVA);
        DllPrinted = TRUE;
    }
    
    if (!strcmp(DecodedInstruction.mnemonic.p, "CALL"))
    {
        if (TraceDepthCount >= TraceDepthLimit)
        {    
#ifdef _WIN64
            ReturnAddress = (PVOID)((PUCHAR)ExceptionInfo->ContextRecord->Rip + DecodedInstruction.size);
#else
            ReturnAddress = (PVOID)((PUCHAR)ExceptionInfo->ContextRecord->Eip + DecodedInstruction.size);
#endif
            if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, BreakpointCallback))
            {
                DoOutputDebugString("Trace: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
            }
            
            ClearSingleStepMode(ExceptionInfo->ContextRecord);
            
            return TRUE;
        }
        else
            TraceDepthCount++;
    }
    else if (!strcmp(DecodedInstruction.mnemonic.p, "RET"))
    {
        if (TraceDepthCount < 0)
        {
            DoOutputDebugString("Trace: Stepping out of initial depth, releasing.");
            
            ClearSingleStepMode(ExceptionInfo->ContextRecord);
            
            return TRUE;
        }
        
        TraceDepthCount--;
    }

    SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
    
    return TRUE;
}

BOOL BreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DecodedInstructionsCount = 0;

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

#ifdef _WIN64
    _DecodeType DecodeType = Decode64Bits;
    Result = distorm_decode(Offset, (const unsigned char*)ExceptionInfo->ContextRecord->Rip, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount); 
    DoOutputDebugString("0x%p (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#else
    _DecodeType DecodeType = Decode32Bits;
    Result = distorm_decode(Offset, (const unsigned char*)ExceptionInfo->ContextRecord->Eip, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount); 
    DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#endif
    
    StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

    DoSetSingleStepMode(pBreakpointInfo->Register, ExceptionInfo->ContextRecord, Trace);
    
    return TRUE;
}

BOOL SetInitialBreakpoints(PVOID ImageBase)
{
    DWORD_PTR BreakpointVA;
    DWORD Register;

    StepCount = 0;
    TraceDepthCount = 0;

    if (!StepLimit)
        StepLimit = SINGLE_STEP_LIMIT;
    
	if (!bp0 && !bp1 && !bp2 && !bp3)
	{
		DoOutputDebugString("SetInitialBreakpoints: Error - No address specified for Trace breakpoints.\n");
		return FALSE;
	}
    
    if (!ImageBase)
    {
        ImageBase = GetModuleHandle(NULL);
        DoOutputDebugString("SetInitialBreakpoints: ImageBase not set by base-on-api parameter, defaulting to process image base 0x%p.\n", ImageBase);
		return FALSE;
    }
    else
        DoOutputDebugString("SetInitialBreakpoints: ImageBase set to 0x%p.\n", ImageBase);
    
    if (bp0)
    {
        Register = 0;
        
        BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)bp0;

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, BP_EXEC, BreakpointCallback))
        {
            DoOutputDebugString("SetInitialBreakpoints: Breakpoint %d set on address 0x%p (RVA 0x%x)\n", Register, BreakpointVA, bp0);
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
            DoOutputDebugString("SetInitialBreakpoints: Breakpoint %d set on address 0x%p (RVA 0x%x)\n", Register, BreakpointVA, bp1);
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
            DoOutputDebugString("SetInitialBreakpoints: Breakpoint %d set on address 0x%p (RVA 0x%x)\n", Register, BreakpointVA, bp2);
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
            DoOutputDebugString("SetInitialBreakpoints: Breakpoint %d set on address 0x%p (RVA 0x%x)\n", Register, BreakpointVA, bp3);
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
