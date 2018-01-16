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
#define SINGLE_STEP_LIMIT 0x10

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);
extern int DumpModuleInCurrentProcess(LPVOID ModuleBase);
extern int DumpMemory(LPVOID Buffer, unsigned int Size);

extern DWORD_PTR FileOffsetToVA(DWORD_PTR modBase, DWORD_PTR dwOffset);

BOOL BreakpointSet;
unsigned int DumpCount, Correction, StepCount;
PVOID ModuleBase, DumpAddress;
SIZE_T DumpSize;

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
        else if (!strncmp(DecodedInstruction.operands.p, "EAX", 3))
        {
            DWORD Constant = *(DWORD*)((unsigned char*)ExceptionInfo->ContextRecord->Rip + 1);
            DoOutputDebugString("SingleStepDisassemble: Comparison detected: RAX (0x%x) vs 0x%x.", ExceptionInfo->ContextRecord->Rax, Constant);
            ExceptionInfo->ContextRecord->Rax = Constant;
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
    
    if (!DumpAddress || !DumpSize)
    {
        DoOutputDebugString("DumpCallback: Error - problem with address 0x%p or size 0x%x.\n", DumpAddress, DumpSize);
        return FALSE;
    }

    if (DumpMemory(DumpAddress, (unsigned int)DumpSize))
    {
        DoOutputDebugString("DumpCallback: Dumped decrypted region at 0x%p, size 0x%x.\n", DumpAddress, DumpSize);
    }
    else
    {
        DoOutputDebugString("DumpCallback: Failed to dump decrypted region at 0x%p, size 0x%x.\n", DumpAddress, DumpSize);
    }
    
    DumpAddress = NULL;
    DumpSize = 0;
    
    ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);
    
    StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
    
    return TRUE;
}

BOOL CryptoCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID ReturnAddress;
    DWORD Register = 1;
    
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

	DoOutputDebugString("CryptoCallback: Breakpoint %i Size=0x%x and Address=0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address);

    DumpAddress = (PVOID)ExceptionInfo->ContextRecord->Rcx;
    DumpSize = (SIZE_T)ExceptionInfo->ContextRecord->Rdx;
    
#ifdef _WIN64
	DoOutputDebugString("CryptoCallback: Source 0x%p, Destination 0x%p, Size=0x%x.\n", ExceptionInfo->ContextRecord->R8, DumpAddress, DumpSize);
    ReturnAddress = (PVOID)*(DWORD_PTR*)(ExceptionInfo->ContextRecord->Rsp);
#else
	DoOutputDebugString("CryptoCallback: Source 0x%p, Destination 0x%p, Size=0x%x.\n", pBreakpointInfo->Register, pBreakpointInfo->Size, DumpSize);
#endif

    
    if (ContextSetBreakpoint(ExceptionInfo->ContextRecord, Register, 0, (BYTE*)ReturnAddress, BP_EXEC, DumpCallback))
    {
        DoOutputDebugString("CryptoCallback: Breakpoint %d set on return address 0x%p\n", Register, ReturnAddress);
    }
    else
    {
        DoOutputDebugString("CryptoCallback: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
    }    
    
    StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
    
    return TRUE;
}

BOOL SetInitialBreakpoint()
{
    DWORD_PTR BreakpointVA, FileOffset;
    DWORD Register = 0;
    
    if (BreakpointSet)
	{
		DoOutputDebugString("SetInitialBreakpoint: Initial breakpoint already set.\n");
		return FALSE;
	}
        
	if (CAPE_var1 == NULL)
	{
		DoOutputDebugString("SetInitialBreakpoint: Error - No address specified for Ursnif decryption function.\n");
		return FALSE;
	}

	if (CAPE_var1)
        FileOffset = (DWORD_PTR)CAPE_var1;
    
    DoOutputDebugString("SetInitialBreakpoint: About to call FileOffsetToVA with image base 0x%p and offset 0x%x.\n", ModuleBase, FileOffset);
    
    BreakpointVA = FileOffsetToVA((DWORD_PTR)ModuleBase, (DWORD_PTR)FileOffset);
    
    if (SetBreakpoint(GetCurrentThreadId(), Register, 0, (BYTE*)BreakpointVA, BP_EXEC, CryptoCallback))
    {
        DoOutputDebugString("SetInitialBreakpoint: Breakpoint %d set on address 0x%p\n", Register, BreakpointVA);
        BreakpointSet = TRUE;
        return TRUE;
    }
    else
    {
        DoOutputDebugString("SetInitialBreakpoint: SetBreakpoint failed.\n");
        BreakpointSet = FALSE;
        return FALSE;
    }
}

//HOOKDEF(LPSTR, WINAPI, lstrcpynA,
//  _Out_ LPSTR   lpString1,
//  _In_  LPSTR   lpString2,
//  _In_  int     iMaxLength
//)
//{
//    const char UrsnifString[] = ".bss";
//    
//    if (!strncmp(lpString2, UrsnifString, strlen(UrsnifString)))
//    {
//        DoOutputDebugString("lstrcpynA hook: Ursnif payload marker.\n");
//        GetHookCallerBase();    
//    }
//    else 
//        DoOutputDebugString("lstrcpynA hook: Unrecognised string: %s.\n", lpString2);
//
//    return Old_lstrcpynA(lpString1, lpString2, iMaxLength);
//}