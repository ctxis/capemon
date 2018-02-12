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
#include "..\hooking.h"
#include <distorm.h>
#include "Debugger.h"
#include "CAPE.h"

#define MAX_INSTRUCTIONS 32
#define SINGLE_STEP_LIMIT 0x20

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

BOOL DumpCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("DumpCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("DumpCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("DumpCallback: Breakpoint %i Size=0x%x and Address=0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);
    
    DoOutputDebugString("DumpCallback: single-step limit reached, dumping module.");
    
    if (!PayloadDumped)
    {
        PayloadDumped = TRUE;   // set this to prevent a second dump
                                // from another thread before the
                                // first is complete
        PayloadDumped = DumpModuleInCurrentProcess(ModuleBase);
        
        if (PayloadDumped)
        {
            DoOutputDebugString("DumpCallback: Succssfully dumped module.");
        }
        else
            DoOutputDebugString("DumpCallback: Module dump failed.");
    }

    ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);
    
    StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
    
    return TRUE;
}

BOOL Trace(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID ReturnAddress;
    DWORD Register = 1;

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
    Result = distorm_decode(Offset, (const unsigned char*)ExceptionInfo->ContextRecord->Rip, 0x10, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount); 
#else
    Result = distorm_decode(Offset, (const unsigned char*)ExceptionInfo->ContextRecord->Eip, 0x10, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount); 
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
            DWORD Constant = *(DWORD*)((unsigned char*)ExceptionInfo->ContextRecord->Rip + 1);
            DoOutputDebugString("Trace: Comparison detected: RCX (0x%x) vs 0x%x.", ExceptionInfo->ContextRecord->Rcx, Constant);
            //ExceptionInfo->ContextRecord->Rcx = Constant;
        }
        else if (!strncmp(DecodedInstruction.operands.p, "R11", 3))
        {
            DWORD Constant = *(DWORD*)((unsigned char*)ExceptionInfo->ContextRecord->Rip + 1);
            DoOutputDebugString("Trace: Comparison detected: R11 (0x%x) vs 0x%x.", ExceptionInfo->ContextRecord->R11, Constant);
            //ExceptionInfo->ContextRecord->R11 = Constant;
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EAX", 3))
        {
            DWORD Constant = *(DWORD*)((unsigned char*)ExceptionInfo->ContextRecord->Rip + 1);
            DoOutputDebugString("Trace: Comparison detected: RAX (0x%x) vs 0x%x.", ExceptionInfo->ContextRecord->Rax, Constant);
            //ExceptionInfo->ContextRecord->Rax = Constant;
        }
#else
        DWORD Constant = *(DWORD*)((unsigned char*)ExceptionInfo->ContextRecord->Eip + 1);
        DoOutputDebugString("Trace: Comparison detected, EAX (0x%x) vs 0x%x.", ExceptionInfo->ContextRecord->Eax, Constant);
        //ExceptionInfo->ContextRecord->Eax = Constant;
#endif
    }
    
    if (!strcmp(DecodedInstruction.mnemonic.p, "CALL"))
    {
#ifdef _WIN64
        ReturnAddress = (PVOID)((PUCHAR)ExceptionInfo->ContextRecord->Rip + DecodedInstruction.size);
#else
        ReturnAddress = (PVOID)((PUCHAR)ExceptionInfo->ContextRecord->Eip + DecodedInstruction.size);
#endif
        if (ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, Register, 0, (BYTE*)ReturnAddress, BP_EXEC, DumpCallback))
        {
            DoOutputDebugString("Trace: Breakpoint %d set on return address 0x%p\n", Register, ReturnAddress);
        }
        else
        {
            DoOutputDebugString("Trace: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
        }
        
        ClearSingleStepMode(ExceptionInfo->ContextRecord);
        
        return TRUE;
    }
    
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

    ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);    
    
    StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

    SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
    
    return TRUE;
}

BOOL ConfigCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    PVOID DumpAddress;
    unsigned int DumpSize = 0, NumOfSections = 0, EntryOffset = 0;
    
	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("ConfigCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}
	
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("ConfigCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("ConfigCallback: Breakpoint %i Size=0x%x and Address=0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

#ifdef _WIN64    
    DumpAddress = (PVOID)ExceptionInfo->ContextRecord->Rcx;
#else
    DumpAddress = (PVOID)*(DWORD*)((PUCHAR)ExceptionInfo->ContextRecord->Ebp+8);
#endif
    
	DoOutputDebugString("ConfigCallback: Config location set to: 0x%p.\n", DumpAddress);
    
    NumOfSections = (unsigned int)(*(DWORD*)DumpAddress);
    
    EntryOffset = 8 + ((NumOfSections - 1)* 24);
    
    DumpSize = EntryOffset + *(DWORD*)((PUCHAR)DumpAddress + EntryOffset + 8);
    
    if (DumpMemory(DumpAddress, DumpSize))
    {
        DoOutputDebugString("ConfigCallback: Dumped config region at 0x%p size 0x%x.\n", DumpAddress, DumpSize);
    }
    else
    {
        DoOutputDebugString("ConfigCallback: Failed to dump config region at 0x%p.\n", DumpAddress);
    }
    
    ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);    
    
    StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

    return TRUE;
}

BOOL SetInitialBreakpoint()
{
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstructions[MAX_INSTRUCTIONS];
    unsigned int DecodedInstructionsCount = 0, ChunkSize, Delta = 0;

    DWORD_PTR BreakpointVA, FileOffset;
    PTHREADBREAKPOINTS CurrentThreadBreakpoints;
    DWORD Register = 0, ThreadId = GetCurrentThreadId();
    
    if (BreakpointSet)
	{
		DoOutputDebugString("SetInitialBreakpoint: Initial breakpoint already set.\n");
		return FALSE;
	}
        
	if (!bp0 && !bp1 && !bp2)
	{
		DoOutputDebugString("SetInitialBreakpoint: Error - No address specified for Ursnif breakpoints.\n");
		return FALSE;
	}

	CurrentThreadBreakpoints = GetThreadBreakpoints(ThreadId);

    if (CurrentThreadBreakpoints == NULL)
    {
        CurrentThreadBreakpoints = CreateThreadBreakpoints(ThreadId);

        if (CurrentThreadBreakpoints == NULL)
        {
            DoOutputDebugString("SetInitialBreakpoint: Failed to create thread breakpoints for current thread %d.\n", ThreadId);
            return FALSE;        
        }
    }
    
    if (CurrentThreadBreakpoints->ThreadHandle == NULL)
    {
		DoOutputDebugString("SetInitialBreakpoint error: thread handle not set (thread %d).\n", ThreadId);
		return FALSE;        
    }
    
    if (bp0)
    {
        FileOffset = (DWORD_PTR)bp0;
        BreakpointVA = FileOffsetToVA((DWORD_PTR)ModuleBase, (DWORD_PTR)FileOffset);
        ChunkSize = 0x10;
        
        memset(&DecodedInstructions, 0, sizeof(DecodedInstructions));
        
#ifdef _WIN64
        _DecodeType DecodeType = Decode64Bits;
#else
        _DecodeType DecodeType = Decode32Bits;
#endif
        
        Result = distorm_decode(Offset, (const unsigned char*)BreakpointVA, ChunkSize, DecodeType, DecodedInstructions, 1, &DecodedInstructionsCount); 

        if (strcmp(DecodedInstructions[0].mnemonic.p, "MOV"))
        {
            DoOutputDebugString("SetInitialBreakpoint: Not within Ursnif payload - bailing.\n");
            BreakpointSet = FALSE;
            return FALSE;
        }
        
        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, BP_EXEC, ConfigCallback))
        {
            DoOutputDebugString("SetInitialBreakpoint: Breakpoint %d set on config parsing function at 0x%p\n", Register, BreakpointVA);
            BreakpointSet = TRUE;
        }
        else
        {
            DoOutputDebugString("SetInitialBreakpoint: SetBreakpoint failed.\n");
            BreakpointSet = FALSE;
            return FALSE;
        }
    }
    
    if (!bp1)
        return TRUE;

    if (bp1)
    {
        Register = 2;
        FileOffset = (DWORD_PTR)bp1;
        BreakpointVA = FileOffsetToVA((DWORD_PTR)ModuleBase, (DWORD_PTR)FileOffset);
        ChunkSize = 0x40;    // Size of code to disassemble
        
        memset(&DecodedInstructions, 0, sizeof(DecodedInstructions));
        
#ifdef _WIN64
        _DecodeType DecodeType = Decode64Bits;
#else
        _DecodeType DecodeType = Decode32Bits;
#endif
        Result = distorm_decode(Offset, (const unsigned char*)BreakpointVA, ChunkSize, DecodeType, DecodedInstructions, MAX_INSTRUCTIONS, &DecodedInstructionsCount); 

        for (unsigned int i = 0; i < DecodedInstructionsCount; i++) 
        {
        
            DoOutputDebugString("%0*I64x (%02d) %-24s %s%s%s\n", DecodeType != Decode64Bits ? 8 : 16, BreakpointVA + Delta, DecodedInstructions[i].size, (char*)DecodedInstructions[i].instructionHex.p, (char*)DecodedInstructions[i].mnemonic.p, DecodedInstructions[i].operands.length != 0 ? " " : "", (char*)DecodedInstructions[i].operands.p); 
        
            if (!strcmp(DecodedInstructions[i].mnemonic.p, "RET"))
            {
                if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA + Delta, BP_EXEC, BreakpointCallback))
                {
                    DoOutputDebugString("SetInitialBreakpoint: Breakpoint %d set on ret instruction at 0x%p (delta 0x%x).\n", Register, BreakpointVA, Delta);
                    return TRUE;
                }
                else
                {
                    DoOutputDebugString("SetInitialBreakpoint: SetBreakpoint failed #2s.\n");
                    return FALSE;
                }
            }
            
            Delta += DecodedInstructions[i].size;
        }
    }
    
    return FALSE;
}

HOOKDEF(LPSTR, WINAPI, lstrcpynA,
  _Out_ LPSTR   lpString1,
  _In_  LPSTR   lpString2,
  _In_  int     iMaxLength
)
{
    LPSTR ret;
    
    const char UrsnifString[] = ".bss";

    ret = Old_lstrcpynA(lpString1, lpString2, iMaxLength);
    
    if (!PayloadMarker && !strncmp(lpString2, UrsnifString, strlen(UrsnifString)))
    {
        DoOutputDebugString("lstrcpynA hook: Ursnif payload marker: %s.\n", lpString2);
        PayloadMarker = TRUE;
        GetHookCallerBase();    
    }

    return ret; 
}
