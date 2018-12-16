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
BOOL Trace2(struct _EXCEPTION_POINTERS* ExceptionInfo);
BOOL BreakpointCallback1(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo);
BOOL BreakpointCallback2(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo);
BOOL BreakpointCallback3(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo);

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
            if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, BreakpointCallback1))
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
    else if (!strcmp(DecodedInstruction.mnemonic.p, "JLE"))
    {
        DoOutputDebugString("Trace: JLE detected, clearing zero flag.\n");
        ClearZeroFlag(ExceptionInfo->ContextRecord);
    }

    SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
    
    return TRUE;
}

BOOL Trace2(struct _EXCEPTION_POINTERS* ExceptionInfo)
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
        DoOutputDebugString("Trace2: single-step limit reached (%d), releasing.", StepLimit);
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
        DoOutputDebugString("Trace2: Tracing in %s (RVA 0x%x).\n", DllName, DllRVA);
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
            if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, BreakpointCallback2))
            {
                DoOutputDebugString("Trace2: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
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
            DoOutputDebugString("Trace2: Stepping out of initial depth, releasing.");
            
            ClearSingleStepMode(ExceptionInfo->ContextRecord);
            
            return TRUE;
        }
        
        TraceDepthCount--;
    }

    SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
    
    return TRUE;
}

BOOL BreakpointCallback1(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DecodedInstructionsCount = 0;

	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("BreakpointCallback1 executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("BreakpointCallback1 executed with NULL thread handle.\n");
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
    
    if (!strcmp(DecodedInstruction.mnemonic.p, "JLE"))
    {
        DoOutputDebugString("Trace: JLE detected, clearing zero flag to bypass anti-sandbox.\n");
        ClearZeroFlag(ExceptionInfo->ContextRecord);
    }

    StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

    DoSetSingleStepMode(pBreakpointInfo->Register, ExceptionInfo->ContextRecord, Trace);
    
    return TRUE;
}

BOOL BreakpointCallback2(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DecodedInstructionsCount = 0;

	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("BreakpointCallback2 executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("BreakpointCallback2 executed with NULL thread handle.\n");
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
    
    if (!strcmp(DecodedInstruction.mnemonic.p, "CALL"))
    {
        DumpSize = (SIZE_T)*(DWORD*)((BYTE*)ExceptionInfo->ContextRecord->Esp+4*3);
        DumpAddress = (PVOID)*(DWORD*)((BYTE*)ExceptionInfo->ContextRecord->Esp+4*4);
        
        DoOutputDebugString("Trace: CALL detected, grabbing size 0x%x and buffer 0x%x from stack.\n", DumpSize, DumpAddress);
        
        if (DumpSize > 0x400)
            DoOutputDebugString("Trace: Size too big, not the config.\n");
        else if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, 2, 0, ((BYTE*)ExceptionInfo->ContextRecord->Eip)+5, BP_EXEC, BreakpointCallback3))
            DoOutputDebugString("Trace: failed to set breakpoint on call return at 0x%x", ((BYTE*)ExceptionInfo->ContextRecord->Eip)+5);
    }
    
    StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

    return TRUE;
}

BOOL BreakpointCallback3(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DecodedInstructionsCount = 0;

	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("BreakpointCallback3 executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("BreakpointCallback3 executed with NULL thread handle.\n");
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
    
    if (DumpSize && DumpAddress && DumpCount < 1)
    {
        CapeMetaData->DumpType = QAKBOT_CONFIG;
        if (DumpMemory(DumpAddress, DumpSize))
        {
            DoOutputDebugString("Trace: dumped QakBot config from 0x%x.\n", DumpAddress);
            DumpCount+=1;
        }
        else
            DoOutputDebugString("Trace: Error - failed to dump config from: 0x%x.\n", DumpAddress);
    }
    else
        DoOutputDebugString("Trace: Error - dump size or dump address not set: 0x%x, 0x%x.\n", DumpAddress, DumpSize);
        
    ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);
    
    StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

    return TRUE;
}

BOOL SetInitialBreakpoints(PVOID ImageBase)
{
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstructions[MAX_INSTRUCTIONS];
    unsigned int DecodedInstructionsCount = 0, ChunkSize, Delta = 0;

    DWORD_PTR BreakpointVA;
    DWORD Register = 0, ThreadId = GetCurrentThreadId();

    DumpCount = 0;
    StepCount = 0;
    TraceDepthCount = 0;

    if (!StepLimit)
        StepLimit = SINGLE_STEP_LIMIT;
    
	if (!bp0 && !bp1)// && !bp2 && !bp3)
	{
		DoOutputDebugString("SetInitialBreakpoints: Error - No address specified for QakBot breakpoints.\n");
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
    
    BreakpointSet = FALSE;

    if (bp0)
    {
        Delta = 0;
        Register = 0;
        BreakpointVA = FileOffsetToVA((DWORD_PTR)ImageBase, (DWORD_PTR)bp0);        
        
        ChunkSize = 0x80;    // Size of code to disassemble
        memset(&DecodedInstructions, 0, sizeof(DecodedInstructions));
        
        _DecodeType DecodeType = Decode32Bits;
        Result = distorm_decode(Offset, (const unsigned char*)BreakpointVA, ChunkSize, DecodeType, DecodedInstructions, 1, &DecodedInstructionsCount); 

        for (unsigned int i = 0; i < DecodedInstructionsCount; i++) 
        {
            DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", BreakpointVA + Delta, DecodedInstructions[i].size, (char*)DecodedInstructions[i].instructionHex.p, (char*)DecodedInstructions[i].mnemonic.p, DecodedInstructions[i].operands.length != 0 ? " " : "", (char*)DecodedInstructions[i].operands.p); 
        
            if (!strcmp(DecodedInstructions[i].mnemonic.p, "JLE"))
            {
                if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA + Delta, BP_EXEC, BreakpointCallback1))
                {
                    DoOutputDebugString("SetInitialBreakpoint: Breakpoint %d set on jle instruction at 0x%x.\n", Register, (BYTE*)BreakpointVA + Delta);
                    BreakpointSet = TRUE;
                    break;
                }
                else
                {
                    DoOutputDebugString("SetInitialBreakpoint: SetBreakpoint failed #1.\n");
                    return FALSE;
                }
            }
            
            Delta += DecodedInstructions[i].size;
        }
    }
    else
        DoOutputDebugString("SetInitialBreakpoint: No breakpoint supplied for QakBot anti-sandbox bypass.\n");

    if (bp1)
    {
        Delta = 0;
        Register = 1;
        BreakpointVA = FileOffsetToVA((DWORD_PTR)ImageBase, (DWORD_PTR)bp1);        
        
        ChunkSize = 0x80;    // Size of code to disassemble
        memset(&DecodedInstructions, 0, sizeof(DecodedInstructions));
        
        _DecodeType DecodeType = Decode32Bits;
        Result = distorm_decode(Offset, (const unsigned char*)BreakpointVA, ChunkSize, DecodeType, DecodedInstructions, 1, &DecodedInstructionsCount); 

        for (unsigned int i = 0; i < DecodedInstructionsCount; i++) 
        {
            DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", BreakpointVA + Delta, DecodedInstructions[i].size, (char*)DecodedInstructions[i].instructionHex.p, (char*)DecodedInstructions[i].mnemonic.p, DecodedInstructions[i].operands.length != 0 ? " " : "", (char*)DecodedInstructions[i].operands.p); 
        
            if (!strcmp(DecodedInstructions[i].mnemonic.p, "CALL"))
            {
                if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA + Delta, BP_EXEC, BreakpointCallback2))
                {
                    DoOutputDebugString("SetInitialBreakpoint: Breakpoint %d set on call instruction at 0x%x.\n", Register, (BYTE*)BreakpointVA + Delta);
                    BreakpointSet = TRUE;
                    break;
                }
                else
                {
                    DoOutputDebugString("SetInitialBreakpoint: SetBreakpoint failed #2.\n");
                    return FALSE;
                }
            }
            
            Delta += DecodedInstructions[i].size;
        }
    }
    else
        DoOutputDebugString("SetInitialBreakpoint: No breakpoint supplied for QakBot config dump.\n");
/*
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
*/    
    return BreakpointSet;
}
