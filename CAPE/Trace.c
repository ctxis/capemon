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
BOOL GetSystemTimeAsFileTimeImported, PayloadMarker, PayloadDumped, TraceRunning;
unsigned int DumpCount, Correction, StepCount, StepLimit, TraceDepthLimit;
int StepOverRegister, TraceDepthCount, EntryPointRegister;

BOOL Trace(struct _EXCEPTION_POINTERS* ExceptionInfo);
BOOL BreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo);

BOOL DoSetSingleStepMode(int Register, PCONTEXT Context, PVOID Handler)
{
    StepOverRegister = Register;
    return SetSingleStepMode(Context, Trace);
}

BOOL Trace(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID ReturnAddress, CIP;
    BOOL StepOver;
#ifdef BRANCH_TRACE
    PVOID BranchTarget;
#endif

    TraceRunning = TRUE;

    _DecodeType DecodeType;
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DecodedInstructionsCount = 0;

#ifdef _WIN64
    CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
    DecodeType = Decode64Bits;
#else
    CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
    DecodeType = Decode32Bits;
#endif
    if (!is_in_dll_range((ULONG_PTR)CIP))
        StepCount++;

    if (StepCount > StepLimit)
    {
        DoOutputDebugString("Trace: single-step limit reached (%d), releasing.", StepLimit);
        StepCount = 0;
        return TRUE;
    }

#ifdef BRANCH_TRACE
    BranchTarget = CIP;
    CIP = (PVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
    DoOutputDebugString("Trace: Branch trace hit with EIP 0x%p, BranchTarget 0x%p.\n", CIP, BranchTarget);
#endif
    Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

    if (!strcmp(DecodedInstruction.mnemonic.p, "CALL"))
    {
        StepOver = FALSE;
        if (is_in_dll_range((ULONG_PTR)CIP)) {
            StepOver = TRUE;
        }
        else if (DecodedInstruction.size > 4 && DecodedInstruction.operands.length && !strncmp(DecodedInstruction.operands.p, "DWORD", 5) && strncmp(DecodedInstruction.operands.p, "DWORD [E", 8))
        {
            PCHAR ExportName;
            PVOID *CallTarget = *(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4);
            __try
            {
                ExportName = ScyllaGetExportNameByAddress(*CallTarget, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DoOutputDebugString("Trace: Error dereferencing CallTarget 0x%x.\n", CallTarget);
            }

            if (ExportName)
            {
                DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%x (%02d) %-24s %s%s0x%x\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", *CallTarget);
        }
        else if (DecodedInstruction.size > 4)
        {
            PCHAR ExportName;
            PVOID CallTarget = (PVOID)((PUCHAR)CIP + (int)*(DWORD*)((PUCHAR)CIP + DecodedInstruction.size - 4));
            __try
            {
                ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DoOutputDebugString("Trace: Error dereferencing CallTarget 0x%x.\n", CallTarget);
            }

            if (ExportName)
            {
                DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%x (%02d) %-24s %s%s0x%x\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
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
                DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%x (%02d) %-24s %s%s0x%x\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
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
                DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%x (%02d) %-24s %s%s0x%x\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
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
                DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%x (%02d) %-24s %s%s0x%x\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
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
                DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%x (%02d) %-24s %s%s0x%x\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EBP", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rbp;
            PCHAR ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DoOutputDebugString("0x%p (%02d) %-24s %s%s0x%p\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%p (%02d) %-24s %s%s0x%p\n", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ebp;
            PCHAR ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DoOutputDebugString("0x%x (%02d) %-24s %s%s0x%x\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else
            DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#ifdef BRANCH_TRACE
        if (!is_in_dll_range((ULONG_PTR)CIP))
            TraceDepthCount++;
#else
        if ((unsigned int)abs(TraceDepthCount) >= TraceDepthLimit || StepOver == TRUE)
        {
            ReturnAddress = (PVOID)((PUCHAR)CIP + DecodedInstruction.size);
            if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, BreakpointCallback))
            {
                DoOutputDebugString("Trace: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
            }
            //else
            //    DoOutputDebugString("Trace: Successfully set breakpoint on return address 0x%p\n", ReturnAddress);

            ClearSingleStepMode(ExceptionInfo->ContextRecord);

            return TRUE;
        }
        else if (!is_in_dll_range((ULONG_PTR)CIP))
            TraceDepthCount++;
#endif
    }
    else if (!strcmp(DecodedInstruction.mnemonic.p, "RET"))
    {
        if (!is_in_dll_range((ULONG_PTR)CIP))
            DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
        //if ((unsigned int)abs(TraceDepthCount) >= TraceDepthLimit)
        //{
        //    DoOutputDebugString("Trace: Stepping out of initial depth, releasing.");
        //
        //    ClearSingleStepMode(ExceptionInfo->ContextRecord);
        //
        //    return TRUE;
        //}

        else if (!is_in_dll_range((ULONG_PTR)CIP))
            TraceDepthCount--;
    }
    else if (!is_in_dll_range((ULONG_PTR)CIP))
    {
        DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
    }

    SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);

    TraceRunning = FALSE;

    return TRUE;
}

BOOL BreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID ReturnAddress, CIP;
    char* ModuleName;
    _DecodeType DecodeType;
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
    CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
    DecodeType = Decode64Bits;
#else
    CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
    DecodeType = Decode32Bits;
#endif
    ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)CIP, &DllRVA);

    if (!ModuleNamePrinted && ModuleName)
    {
        DoOutputDebugString("BreakpointCallback: Break in %s (RVA 0x%x).\n", ModuleName, DllRVA);
        ModuleNamePrinted = TRUE;
    }

    Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);
    if (!is_in_dll_range((ULONG_PTR)CIP))
        DoOutputDebugString("0x%x (%02d) %-24s %s%s%s\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);

    if (!strcmp(DecodedInstruction.mnemonic.p, "CALL"))
    {
#ifdef BRANCH_TRACE
        if (!is_in_dll_range((ULONG_PTR)CIP))
            TraceDepthCount++;
#else
        if ((unsigned int)abs(TraceDepthCount) >= TraceDepthLimit)
        {
            ReturnAddress = (PVOID)((PUCHAR)CIP + DecodedInstruction.size);
            if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, 0, (BYTE*)ReturnAddress, BP_EXEC, BreakpointCallback))
            {
                DoOutputDebugString("BreakpointCallback: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
            }

            StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

            return TRUE;
        }
        else if (!is_in_dll_range((ULONG_PTR)CIP))
            TraceDepthCount++;
#endif
}
    else if (!strcmp(DecodedInstruction.mnemonic.p, "RET"))
    {
        if (TraceDepthCount < 0)
        {
            DoOutputDebugString("BreakpointCallback: Stepping out of initial depth, releasing.");

            StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

            return TRUE;
        }
        else if (!is_in_dll_range((ULONG_PTR)CIP))
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

#ifdef STANALONE
    TraceDepthLimit = 5;
#endif
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
