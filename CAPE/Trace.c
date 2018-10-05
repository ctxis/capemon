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
#define SINGLE_STEP_LIMIT 0x200  // default unless specified in web ui
#define CHUNKSIZE 0x10 * MAX_INSTRUCTIONS

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);
extern int DumpModuleInCurrentProcess(LPVOID ModuleBase);
extern int DumpMemory(LPVOID Buffer, SIZE_T Size);
extern char *convert_address_to_dll_name_and_offset(ULONG_PTR addr, unsigned int *offset);
extern BOOL is_in_dll_range(ULONG_PTR addr);
extern DWORD_PTR FileOffsetToVA(DWORD_PTR modBase, DWORD_PTR dwOffset);
extern DWORD_PTR GetEntryPointVA(DWORD_PTR modBase);
extern BOOL ScyllaGetSectionByName(PVOID ImageBase, char* Name, PVOID* SectionData, SIZE_T* SectionSize);
extern PCHAR ScyllaGetExportNameByAddress(PVOID Address, PCHAR* ModuleName);

BOOL BreakpointsSet, ModuleNamePrinted;
PVOID ModuleBase, DumpAddress;
SIZE_T DumpSize;
BOOL GetSystemTimeAsFileTimeImported, PayloadMarker, PayloadDumped;
unsigned int DumpCount, Correction, StepCount, StepLimit;
int StepOverRegister, TraceDepthCount, TraceDepthLimit, EntryPointRegister;

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
    BOOL StepOver;

    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DecodedInstructionsCount = 0;

#ifdef _WIN64
    if (!is_in_dll_range(ExceptionInfo->ContextRecord->Rip))
#else
    if (!is_in_dll_range(ExceptionInfo->ContextRecord->Eip))
#endif
        StepCount++;

    if (StepCount > StepLimit)
    {
        DoOutputDebugString("Trace: single-step limit reached (%d), releasing.", StepLimit);
        StepCount = 0;
        return TRUE;
    }

#ifdef _WIN64
    Result = distorm_decode(Offset, (const unsigned char*)ExceptionInfo->ContextRecord->Rip, CHUNKSIZE, Decode64Bits, &DecodedInstruction, 1, &DecodedInstructionsCount);
#else
    Result = distorm_decode(Offset, (const unsigned char*)ExceptionInfo->ContextRecord->Eip, CHUNKSIZE, Decode32Bits, &DecodedInstruction, 1, &DecodedInstructionsCount);
#endif

    if (!strcmp(DecodedInstruction.mnemonic.p, "CALL"))
    {
        StepOver = FALSE;
#ifdef _WIN64
        if (is_in_dll_range(ExceptionInfo->ContextRecord->Rip)) {
            StepOver = TRUE;
        }
        else if (DecodedInstruction.size > 4 && DecodedInstruction.operands.length && !strncmp(DecodedInstruction.operands.p, "QWORD", 5))
        {
            PCHAR ExportName;
            PVOID *CallTarget = (PVOID*)((PUCHAR)ExceptionInfo->ContextRecord->Rip + (unsigned int)*(DWORD*)((PUCHAR)ExceptionInfo->ContextRecord->Rip + DecodedInstruction.size - 4) + DecodedInstruction.size);
            __try
            {
                ExportName = ScyllaGetExportNameByAddress(*CallTarget, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DoOutputDebugString("Trace: Error dereferencing CallTarget 0x%p.\n", CallTarget);
                return FALSE;
            }

            if (ExportName)
            {
                DoOutputDebugString("0x%p (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%p (%02d) %-24s %s%s0x%p\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", *CallTarget);

#else
        if (is_in_dll_range(ExceptionInfo->ContextRecord->Eip)) {
            StepOver = TRUE;
        }
        else if (DecodedInstruction.size > 4 && DecodedInstruction.operands.length && !strncmp(DecodedInstruction.operands.p, "DWORD", 5) && strncmp(DecodedInstruction.operands.p, "DWORD [E", 8))
        {
            PCHAR ExportName;
            PVOID *CallTarget = *(PVOID*)((PUCHAR)ExceptionInfo->ContextRecord->Eip + DecodedInstruction.size - 4);
            __try
            {
                ExportName = ScyllaGetExportNameByAddress(*CallTarget, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DoOutputDebugString("Trace: Error dereferencing CallTarget 0x%x.\n", CallTarget);
                return FALSE;
            }

            if (ExportName)
            {
                DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%x (%02d) %-24s %s%s0x%x\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", *CallTarget);
#endif
        }
        else if (DecodedInstruction.size > 4)
        {
#ifdef _WIN64
            PCHAR ExportName;
            PVOID CallTarget = (PVOID)(ExceptionInfo->ContextRecord->Rip + (unsigned int)*(DWORD*)((PUCHAR)ExceptionInfo->ContextRecord->Rip + DecodedInstruction.size - 4));
            __try
            {
                ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DoOutputDebugString("Trace: Error dereferencing CallTarget 0x%p.\n", CallTarget);
                return FALSE;
            }

            if (ExportName)
            {
                DoOutputDebugString("0x%p (%02d) %-24s %s%s0x%p\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%p (%02d) %-24s %s%s0x%p\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PCHAR ExportName;
            PVOID CallTarget = (PVOID)(ExceptionInfo->ContextRecord->Eip + (int)*(DWORD*)((PUCHAR)ExceptionInfo->ContextRecord->Eip + DecodedInstruction.size - 4));
            __try
            {
                ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DoOutputDebugString("Trace: Error dereferencing CallTarget 0x%x.\n", CallTarget);
                return FALSE;
            }

            if (ExportName)
            {
                DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%x (%02d) %-24s %s%s0x%x\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EAX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rax;
            PCHAR ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DoOutputDebugString("0x%p (%02d) %-24s %s%s0x%p\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%p (%02d) %-24s %s%s0x%p\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Eax;
            PCHAR ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%x (%02d) %-24s %s%s0x%x\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EBX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rbx;
            PCHAR ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DoOutputDebugString("0x%p (%02d) %-24s %s%s0x%p\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%p (%02d) %-24s %s%s0x%p\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ebx;
            PCHAR ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%x (%02d) %-24s %s%s0x%x\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "ECX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rcx;
            PCHAR ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DoOutputDebugString("0x%p (%02d) %-24s %s%s0x%p\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%p (%02d) %-24s %s%s0x%p\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ecx;
            PCHAR ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%x (%02d) %-24s %s%s0x%x\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EDX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rdx;
            PCHAR ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DoOutputDebugString("0x%p (%02d) %-24s %s%s0x%p\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%p (%02d) %-24s %s%s0x%p\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Edx;
            PCHAR ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%x (%02d) %-24s %s%s0x%x\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else
#ifdef _WIN64
            DoOutputDebugString("0x%p (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#else
            DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#endif
        
        if (TraceDepthCount >= TraceDepthLimit || StepOver == TRUE)
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
            else
                DoOutputDebugString("Trace: Successfully set breakpoint on return address 0x%p\n", ReturnAddress);

            ClearSingleStepMode(ExceptionInfo->ContextRecord);

            return TRUE;
        }
#ifdef _WIN64
        else if (!is_in_dll_range(ExceptionInfo->ContextRecord->Rip))
#else
        else if (!is_in_dll_range(ExceptionInfo->ContextRecord->Eip))
#endif
            TraceDepthCount++;
    }
    else if (!strcmp(DecodedInstruction.mnemonic.p, "RET"))
    {
#ifdef _WIN64
        if (!is_in_dll_range(ExceptionInfo->ContextRecord->Rip))
            DoOutputDebugString("0x%p (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#else
        if (!is_in_dll_range(ExceptionInfo->ContextRecord->Eip))
            DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#endif
        if (TraceDepthCount < 0)
        {
            DoOutputDebugString("Trace: Stepping out of initial depth, releasing.");

            ClearSingleStepMode(ExceptionInfo->ContextRecord);

            return TRUE;
        }

#ifdef _WIN64
        else if (!is_in_dll_range(ExceptionInfo->ContextRecord->Rip))
#else
        else if (!is_in_dll_range(ExceptionInfo->ContextRecord->Eip))
#endif
            TraceDepthCount--;
    }
#ifdef _WIN64
    else if (!is_in_dll_range(ExceptionInfo->ContextRecord->Rip))
    {
        DoOutputDebugString("0x%p (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#else
    else if (!is_in_dll_range(ExceptionInfo->ContextRecord->Eip))
    {
        DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#endif
    }

    SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
    
    return TRUE;
}

BOOL BreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID ReturnAddress;
    char* ModuleName;
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DllRVA, DecodedInstructionsCount = 0;

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
    ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)ExceptionInfo->ContextRecord->Rip, &DllRVA);
#else
    ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)ExceptionInfo->ContextRecord->Eip, &DllRVA);
#endif

    if (!ModuleNamePrinted && ModuleName)
    {
        DoOutputDebugString("BreakpointCallback: Break in %s (RVA 0x%x).\n", ModuleName, DllRVA);
        ModuleNamePrinted = TRUE;
    }

#ifdef _WIN64
    Result = distorm_decode(Offset, (const unsigned char*)ExceptionInfo->ContextRecord->Rip, CHUNKSIZE, Decode64Bits, &DecodedInstruction, 1, &DecodedInstructionsCount); 
    if (!is_in_dll_range(ExceptionInfo->ContextRecord->Rip))
        DoOutputDebugString("0x%p (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#else
    Result = distorm_decode(Offset, (const unsigned char*)ExceptionInfo->ContextRecord->Eip, CHUNKSIZE, Decode32Bits, &DecodedInstruction, 1, &DecodedInstructionsCount); 
    if (!is_in_dll_range(ExceptionInfo->ContextRecord->Eip))
        DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", ExceptionInfo->ContextRecord->Eip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#endif

    if (!strcmp(DecodedInstruction.mnemonic.p, "CALL"))
    {
        if (TraceDepthCount >= TraceDepthLimit)
        {
#ifdef _WIN64
            ReturnAddress = (PVOID)((PUCHAR)ExceptionInfo->ContextRecord->Rip + DecodedInstruction.size);
#else
            ReturnAddress = (PVOID)((PUCHAR)ExceptionInfo->ContextRecord->Eip + DecodedInstruction.size);
#endif
            if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, 0, (BYTE*)ReturnAddress, BP_EXEC, BreakpointCallback))
            {
                DoOutputDebugString("BreakpointCallback: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
            }

            StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

            return TRUE;
        }
#ifdef _WIN64
        else if (!is_in_dll_range(ExceptionInfo->ContextRecord->Rip))
#else
        else if (!is_in_dll_range(ExceptionInfo->ContextRecord->Eip))
#endif
            TraceDepthCount++;
    }
    else if (!strcmp(DecodedInstruction.mnemonic.p, "RET"))
    {
        if (TraceDepthCount < 0)
        {
            DoOutputDebugString("BreakpointCallback: Stepping out of initial depth, releasing.");

            StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

            return TRUE;
        }
#ifdef _WIN64
        else if (!is_in_dll_range(ExceptionInfo->ContextRecord->Rip))
#else
        else if (!is_in_dll_range(ExceptionInfo->ContextRecord->Eip))
#endif
            TraceDepthCount--;
    }

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
    
	if (!bp0 && !bp1 && !bp2 && !bp3 && !EntryPointRegister)
	{
		DoOutputDebugString("SetInitialBreakpoints: No address specified for Trace breakpoints, defaulting to bp0 on entry point.\n");
		EntryPointRegister = 1;
	}
    
    if (!ImageBase)
    {
        ImageBase = GetModuleHandle(NULL);
        DoOutputDebugString("SetInitialBreakpoints: ImageBase not set by base-on-api parameter, defaulting to process image base 0x%p.\n", ImageBase);
		return FALSE;
    }
    else
        DoOutputDebugString("SetInitialBreakpoints: ImageBase set to 0x%p.\n", ImageBase);
    
    if (EntryPointRegister)
    {
        PVOID EntryPoint = (PVOID)GetEntryPointVA((DWORD_PTR)ImageBase);

        if (EntryPoint)
        {
            Register = EntryPointRegister - 1;

            if (SetBreakpoint(Register, 0, (BYTE*)EntryPoint, BP_EXEC, BreakpointCallback))
            {
                DoOutputDebugString("SetInitialBreakpoints: Breakpoint %d set on entry point at 0x%p.\n", Register, EntryPoint);
                BreakpointsSet = TRUE;
            }
            else
            {
                DoOutputDebugString("SetInitialBreakpoints: SetBreakpoint on entry point failed.\n");
                BreakpointsSet = FALSE;
                return FALSE;
            }
        }
    }

    if (bp0)
    {
        Register = 0;
        
        BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)bp0;

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, BP_EXEC, BreakpointCallback))
        {
            DoOutputDebugString("SetInitialBreakpoints: Breakpoint %d set on address 0x%p (RVA 0x%x)\n", Register, BreakpointVA, bp0);
            BreakpointsSet = TRUE;
        }
        else
        {
            DoOutputDebugString("SetInitialBreakpoints: SetBreakpoint failed.\n");
            BreakpointsSet = FALSE;
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
            BreakpointsSet = TRUE;
        }
        else
        {
            DoOutputDebugString("SetInitialBreakpoints: SetBreakpoint failed.\n");
            BreakpointsSet = FALSE;
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
            BreakpointsSet = TRUE;
        }
        else
        {
            DoOutputDebugString("SetInitialBreakpoints: SetBreakpoint failed.\n");
            BreakpointsSet = FALSE;
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
            BreakpointsSet = TRUE;
        }
        else
        {
            DoOutputDebugString("SetInitialBreakpoints: SetBreakpoint failed.\n");
            BreakpointsSet = FALSE;
            return FALSE;
        }
    }
    
    return BreakpointsSet;
}
