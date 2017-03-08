/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2015 Cuckoo Sandbox Developers, Optiv, Inc. (brad.spengler@optiv.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include "ntapi.h"
#include <tlhelp32.h>
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include "ignore.h"
#include "hook_sleep.h"
#include "unhook.h"
#include "config.h"
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"

#define EXTRACTION_MIN_SIZE 0x2000

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);
extern BOOL SetInitialWriteBreakpoint(PVOID *Address, SIZE_T RegionSize);
extern BOOL ShellCodeExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo);
extern BOOL MidPageExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo);
extern BOOL SetMidPageBreakpoint(PVOID *Address, SIZE_T Size);
extern BOOL AllocationWriteDetected;
extern BOOL AllocationBaseWriteBpSet;
extern BOOL AllocationBaseExecBpSet;
extern BOOL PeImageDetected;
extern BOOL AllocationDumped;
extern PVOID AllocationBase;
extern SIZE_T AllocationSize;
extern int DumpImageInCurrentProcess(DWORD ModuleBase);
extern int DumpMemory(LPCVOID Buffer, unsigned int Size);
extern int ScanForPE(LPCVOID Buffer, unsigned int Size, LPCVOID* Offset);
extern int IsDisguisedPE(LPCVOID Buffer, unsigned int Size);
extern void ExtractionClearAll(void);

HOOKDEF(HANDLE, WINAPI, CreateToolhelp32Snapshot,
	__in DWORD dwFlags,
	__in DWORD th32ProcessID
) {
	HANDLE ret = Old_CreateToolhelp32Snapshot(dwFlags, th32ProcessID);

	LOQ_handle("process", "hi", "Flags", dwFlags, "ProcessId", th32ProcessID);

	return ret;
}

HOOKDEF(BOOL, WINAPI, Process32NextW,
	__in HANDLE hSnapshot,
	__out LPPROCESSENTRY32W lppe
	) {
	BOOL ret = Old_Process32NextW(hSnapshot, lppe);

	/* skip returning protected processes */
	while (ret && lppe && is_protected_pid(lppe->th32ProcessID))
		ret = Old_Process32NextW(hSnapshot, lppe);

	if (ret)
		LOQ_bool("process", "ui", "ProcessName", lppe->szExeFile, "ProcessId", lppe->th32ProcessID);
	else
		LOQ_bool("process", "");

	return ret;
}

HOOKDEF(BOOL, WINAPI, Process32FirstW,
	__in HANDLE hSnapshot,
	__out LPPROCESSENTRY32W lppe
	) {
	BOOL ret = Old_Process32FirstW(hSnapshot, lppe);

	/* skip returning protected processes */
	while (ret && lppe && is_protected_pid(lppe->th32ProcessID))
		ret = Old_Process32NextW(hSnapshot, lppe);

	if (ret)
		LOQ_bool("process", "ui", "ProcessName", lppe->szExeFile, "ProcessId", lppe->th32ProcessID);
	else
		LOQ_bool("process", "");

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateProcess,
    __out       PHANDLE ProcessHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        HANDLE ParentProcess,
    __in        BOOLEAN InheritObjectTable,
    __in_opt    HANDLE SectionHandle,
    __in_opt    HANDLE DebugPort,
    __in_opt    HANDLE ExceptionPort
) {
    NTSTATUS ret = Old_NtCreateProcess(ProcessHandle, DesiredAccess,
        ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle,
        DebugPort, ExceptionPort);
    LOQ_ntstatus("process", "PphO", "ProcessHandle", ProcessHandle, "ParentHandle", ParentProcess, "DesiredAccess", DesiredAccess,
        "FileName", ObjectAttributes);
    if(NT_SUCCESS(ret)) {
		DWORD pid = pid_from_process_handle(*ProcessHandle);
        pipe("PROCESS:%d:%d", is_suspended(pid, 0), pid);
        disable_sleep_skip();
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateProcessEx,
    __out       PHANDLE ProcessHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        HANDLE ParentProcess,
    __in        ULONG Flags,
    __in_opt    HANDLE SectionHandle,
    __in_opt    HANDLE DebugPort,
    __in_opt    HANDLE ExceptionPort,
    __in        BOOLEAN InJob
) {
    NTSTATUS ret = Old_NtCreateProcessEx(ProcessHandle, DesiredAccess,
        ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort,
        ExceptionPort, InJob);
	LOQ_ntstatus("process", "PphO", "ProcessHandle", ProcessHandle, "ParentHandle", ParentProcess, "DesiredAccess", DesiredAccess,
        "FileName", ObjectAttributes);
    if(NT_SUCCESS(ret)) {
		DWORD pid = pid_from_process_handle(*ProcessHandle);
        pipe("PROCESS:%d:%d", is_suspended(pid, 0), pid);
        disable_sleep_skip();
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateUserProcess,
    __out       PHANDLE ProcessHandle,
    __out       PHANDLE ThreadHandle,
    __in        ACCESS_MASK ProcessDesiredAccess,
    __in        ACCESS_MASK ThreadDesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    __in_opt    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    __in        ULONG ProcessFlags,
    __in        ULONG ThreadFlags,
    __in_opt    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    __inout     PPS_CREATE_INFO CreateInfo,
    __in_opt    PPS_ATTRIBUTE_LIST AttributeList
) {
    RTL_USER_PROCESS_PARAMETERS _ProcessParameters;
	NTSTATUS ret;

	memset(&_ProcessParameters, 0, sizeof(_ProcessParameters));

	if(ProcessParameters == NULL)
		ProcessParameters = &_ProcessParameters;

    ret = Old_NtCreateUserProcess(ProcessHandle, ThreadHandle,
        ProcessDesiredAccess, ThreadDesiredAccess,
        ProcessObjectAttributes, ThreadObjectAttributes,
        ProcessFlags, ThreadFlags | 1, ProcessParameters,
        CreateInfo, AttributeList);
    LOQ_ntstatus("process", "PPhhOOoo", "ProcessHandle", ProcessHandle,
        "ThreadHandle", ThreadHandle,
        "ProcessDesiredAccess", ProcessDesiredAccess,
        "ThreadDesiredAccess", ThreadDesiredAccess,
        "ProcessFileName", ProcessObjectAttributes,
        "ThreadName", ThreadObjectAttributes,
        "ImagePathName", &ProcessParameters->ImagePathName,
        "CommandLine", &ProcessParameters->CommandLine);
    if(NT_SUCCESS(ret)) {
		DWORD pid = pid_from_process_handle(*ProcessHandle);
		DWORD tid = tid_from_thread_handle(*ThreadHandle);
		pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);
		if (!(ThreadFlags & 1))
			ResumeThread(*ThreadHandle);
        disable_sleep_skip();
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, RtlCreateUserProcess,
    IN      PUNICODE_STRING ImagePath,
    IN      ULONG ObjectAttributes,
    IN OUT  PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    IN      PSECURITY_DESCRIPTOR ProcessSecurityDescriptor OPTIONAL,
    IN      PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
    IN      HANDLE ParentProcess,
    IN      BOOLEAN InheritHandles,
    IN      HANDLE DebugPort OPTIONAL,
    IN      HANDLE ExceptionPort OPTIONAL,
    OUT     PRTL_USER_PROCESS_INFORMATION ProcessInformation
) {
    NTSTATUS ret = Old_RtlCreateUserProcess(ImagePath, ObjectAttributes,
        ProcessParameters, ProcessSecurityDescriptor,
        ThreadSecurityDescriptor, ParentProcess, InheritHandles, DebugPort,
        ExceptionPort, ProcessInformation);
    LOQ_ntstatus("process", "ohp", "ImagePath", ImagePath, "ObjectAttributes", ObjectAttributes,
        "ParentHandle", ParentProcess);
    if(NT_SUCCESS(ret)) {
		DWORD pid = pid_from_process_handle(ProcessInformation->ProcessHandle);
		DWORD tid = tid_from_thread_handle(ProcessInformation->ThreadHandle);
		pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);
        disable_sleep_skip();
    }
    return ret;
}

HOOKDEF(BOOL, WINAPI, CreateProcessWithLogonW,
	_In_        LPCWSTR               lpUsername,
	_In_opt_    LPCWSTR               lpDomain,
	_In_        LPCWSTR               lpPassword,
	_In_        DWORD                 dwLogonFlags,
	_In_opt_    LPCWSTR               lpApplicationName,
	_Inout_opt_ LPWSTR                lpCommandLine,
	_In_        DWORD                 dwCreationFlags,
	_In_opt_    LPVOID                lpEnvironment,
	_In_opt_    LPCWSTR               lpCurrentDirectory,
	_In_        LPSTARTUPINFOW        lpStartupInfo,
	_Out_       LPPROCESS_INFORMATION lpProcessInfo
) {
	BOOL ret;
	LPWSTR origcommandline = NULL;
	
	if (lpCommandLine)
		origcommandline = wcsdup(lpCommandLine);

	ret = Old_CreateProcessWithLogonW(lpUsername, lpDomain, lpPassword, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInfo);

	LOQ_bool("process", "uuuhuuhiipp", "Username", lpUsername, "Domain", lpDomain, "Password", lpPassword, "LogonFlags", dwLogonFlags, "ApplicationName", lpApplicationName, "CommandLine", origcommandline, "CreationFlags", dwCreationFlags,
		"ProcessId", lpProcessInfo->dwProcessId, "ThreadId", lpProcessInfo->dwThreadId, "ProcessHandle", lpProcessInfo->hProcess, "ThreadHandle", lpProcessInfo->hThread);

	if (origcommandline)
		free(origcommandline);

	if (ret) {
		pipe("PROCESS:%d:%d,%d", is_suspended(lpProcessInfo->dwProcessId, lpProcessInfo->dwThreadId), lpProcessInfo->dwProcessId, lpProcessInfo->dwThreadId);
		if (!(dwCreationFlags & CREATE_SUSPENDED))
			ResumeThread(lpProcessInfo->hThread);
		disable_sleep_skip();
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, CreateProcessWithTokenW,
	_In_        HANDLE                hToken,
	_In_        DWORD                 dwLogonFlags,
	_In_opt_    LPCWSTR               lpApplicationName,
	_Inout_opt_ LPWSTR                lpCommandLine,
	_In_        DWORD                 dwCreationFlags,
	_In_opt_    LPVOID                lpEnvironment,
	_In_opt_    LPCWSTR               lpCurrentDirectory,
	_In_        LPSTARTUPINFOW        lpStartupInfo,
	_Out_       LPPROCESS_INFORMATION lpProcessInfo
) {
	BOOL ret;
	LPWSTR origcommandline = NULL;

	if (lpCommandLine)
		origcommandline = wcsdup(lpCommandLine);

	ret = Old_CreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInfo);

	LOQ_bool("process", "huuhiipp", "LogonFlags", dwLogonFlags, "ApplicationName", lpApplicationName, "CommandLine", origcommandline, "CreationFlags", dwCreationFlags,
		"ProcessId", lpProcessInfo->dwProcessId, "ThreadId", lpProcessInfo->dwThreadId, "ProcessHandle", lpProcessInfo->hProcess, "ThreadHandle", lpProcessInfo->hThread);

	if (origcommandline)
		free(origcommandline);

	if (ret) {
		pipe("PROCESS:%d:%d,%d", is_suspended(lpProcessInfo->dwProcessId, lpProcessInfo->dwThreadId), lpProcessInfo->dwProcessId, lpProcessInfo->dwThreadId);
		if (!(dwCreationFlags & CREATE_SUSPENDED))
			ResumeThread(lpProcessInfo->hThread);
		disable_sleep_skip();
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenProcess,
    __out     PHANDLE ProcessHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in      POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt  PCLIENT_ID ClientId
) {
    // although the documentation on msdn is a bit vague, this seems correct
    // for both XP and Vista (the ClientId->UniqueProcess part, that is)

    int pid = 0;
	NTSTATUS ret;

    if(ClientId != NULL) {
		__try {
			pid = (int)(ULONG_PTR)ClientId->UniqueProcess;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
    }

    if(is_protected_pid(pid)) {
        ret = STATUS_ACCESS_DENIED;
        LOQ_ntstatus("process", "ppl", "ProcessHandle", NULL, "DesiredAccess", DesiredAccess,
            "ProcessIdentifier", pid);
        return ret;
    }

    ret = Old_NtOpenProcess(ProcessHandle, DesiredAccess,
        ObjectAttributes, ClientId);
    LOQ_ntstatus("process", "Phi", "ProcessHandle", ProcessHandle,
        "DesiredAccess", DesiredAccess,
        "ProcessIdentifier", pid);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtResumeProcess,
	__in  HANDLE ProcessHandle
) {
	NTSTATUS ret;
	DWORD pid = pid_from_process_handle(ProcessHandle);
	pipe("RESUME:%d", pid);

	ret = Old_NtResumeProcess(ProcessHandle);
	LOQ_ntstatus("process", "p", "ProcessHandle", ProcessHandle);
	return ret;
}


int process_shutting_down;

HOOKDEF(NTSTATUS, WINAPI, NtTerminateProcess,
    __in_opt  HANDLE ProcessHandle,
    __in      NTSTATUS ExitStatus
) {
	// Process will terminate. Default logging will not work. Be aware: return value not valid
    PBYTE PEImage;
    PIMAGE_DOS_HEADER pDosHeader;
	LPCVOID PEPointer;
	lasterror_t lasterror;
	MEMORY_BASIC_INFORMATION MemInfo;
    NTSTATUS ret = 0;

	get_lasterrors(&lasterror);
	if (ProcessHandle == NULL) {
		// we mark this here as this termination type will kill all threads but ours, including
		// the logging thread.  By setting this, we'll switch into a direct logging mode
		// for the subsequent call to NtTerminateProcess against our own process handle
        if (AllocationBase && AllocationSize && !AllocationDumped)
        {
            if (ScanForNonZero(AllocationBase, AllocationSize))
            {
                DoOutputDebugString("NtTerminateProcess hook: attempting CAPE dump on region: 0x%x.\n", AllocationBase);

                AllocationDumped = TRUE;
                PEPointer = NULL;
                memset(&MemInfo, 0, sizeof(MemInfo));
                VirtualQuery(AllocationBase, &MemInfo, sizeof(MemInfo));
                
                if (PeImageDetected || ScanForPE(MemInfo.AllocationBase, MemInfo.RegionSize, &PEPointer))
                {
                    if (PEPointer)
                        AllocationDumped = DumpImageInCurrentProcess((DWORD)PEPointer);
                    else
                        AllocationDumped = DumpImageInCurrentProcess((DWORD)AllocationBase);
                    
                    if (!AllocationDumped)
                    {
                        AllocationDumped = TRUE;
                        AllocationDumped = DumpMemory(AllocationBase, AllocationSize);
                        
                        if (!AllocationDumped)
                        {
                            DoOutputDebugString("NtTerminateProcess hook: failed to dump memory range at 0x%x.\n", AllocationBase);
                        }
                        else
                        {
                            DoOutputDebugString("NtTerminateProcess hook: successfully dumped memory range.\n");
                            ClearBreakpointsInRange(GetCurrentThreadId(), AllocationBase, AllocationSize);       
                        }
                    }
                    else
                    {
                        DoOutputDebugString("NtTerminateProcess hook: successfully dumped module.\n");
                        ClearBreakpointsInRange(GetCurrentThreadId(), AllocationBase, AllocationSize);       
                    }
                }
                else if (IsDisguisedPE(MemInfo.AllocationBase, MemInfo.RegionSize))
                {
                    // Fix the PE header in the dump
                    pDosHeader = (PIMAGE_DOS_HEADER)MemInfo.AllocationBase;
                    PEImage = (BYTE*)malloc(MemInfo.RegionSize);
                    memcpy(PEImage, MemInfo.AllocationBase, MemInfo.RegionSize);

                    *(WORD*)PEImage = IMAGE_DOS_SIGNATURE;
                    *(DWORD*)(PEImage + pDosHeader->e_lfanew) = IMAGE_NT_SIGNATURE;

                    DumpImageInCurrentProcess((DWORD)PEImage);
                    
                    free(PEImage);

                    DoOutputDebugString("NtTerminateProcess hook: Dumped disguised PE payload.");
                }
                else
                {
                    AllocationDumped = DumpMemory(AllocationBase, AllocationSize);

                    if (!AllocationDumped)
                    {
                        DoOutputDebugString("NtTerminateProcess hook: failed to dump memory range at 0x%x.\n", AllocationBase);
                    }
                    else
                    {
                        DoOutputDebugString("NtTerminateProcess hook: successfully dumped memory range.\n");
                        ClearBreakpointsInRange(GetCurrentThreadId(), AllocationBase, AllocationSize);       
                    }
                }
            }
            else
            {
                DoOutputDebugString("NtTerminateProcess hook: CAPE ignoring region: 0x%x as it is empty.\n", AllocationBase);
                ExtractionClearAll();
            }
        }

        process_shutting_down = 1;
		LOQ_ntstatus("process", "ph", "ProcessHandle", ProcessHandle, "ExitCode", ExitStatus);
	}
	else if (GetCurrentProcessId() == our_getprocessid(ProcessHandle)) {
        if (AllocationBase && AllocationSize && !AllocationDumped)
        {
            if (ScanForNonZero(AllocationBase, AllocationSize))
            {
                DoOutputDebugString("NtTerminateProcess hook: attempting CAPE dump on region: 0x%x.\n", AllocationBase);

                AllocationDumped = TRUE;
                PEPointer = NULL;
                memset(&MemInfo, 0, sizeof(MemInfo));
                VirtualQuery(AllocationBase, &MemInfo, sizeof(MemInfo));
                
                if (PeImageDetected || ScanForPE(MemInfo.AllocationBase, MemInfo.RegionSize, &PEPointer))
                {
                    if (PEPointer)
                        AllocationDumped = DumpImageInCurrentProcess((DWORD)PEPointer);
                    else
                        AllocationDumped = DumpImageInCurrentProcess((DWORD)AllocationBase);
                    
                    if (!AllocationDumped)
                    {
                        AllocationDumped = TRUE;
                        AllocationDumped = DumpMemory(AllocationBase, AllocationSize);
                        
                        if (!AllocationDumped)
                        {
                            DoOutputDebugString("NtTerminateProcess hook: failed to dump memory range at 0x%x.\n", AllocationBase);
                        }
                        else
                        {
                            DoOutputDebugString("NtTerminateProcess hook: successfully dumped memory range.\n");
                            ClearBreakpointsInRange(GetCurrentThreadId(), AllocationBase, AllocationSize);       
                        }
                    }
                    else
                    {
                        DoOutputDebugString("NtTerminateProcess hook: successfully dumped module.\n");
                        ClearBreakpointsInRange(GetCurrentThreadId(), AllocationBase, AllocationSize);       
                    }
                }
                else if (IsDisguisedPE(MemInfo.AllocationBase, MemInfo.RegionSize))
                {
                    // Fix the PE header in the dump
                    pDosHeader = (PIMAGE_DOS_HEADER)MemInfo.AllocationBase;
                    PEImage = (BYTE*)malloc(MemInfo.RegionSize);
                    memcpy(PEImage, MemInfo.AllocationBase, MemInfo.RegionSize);

                    *(WORD*)PEImage = IMAGE_DOS_SIGNATURE;
                    *(DWORD*)(PEImage + pDosHeader->e_lfanew) = IMAGE_NT_SIGNATURE;

                    DumpImageInCurrentProcess((DWORD)PEImage);
                    
                    free(PEImage);

                    DoOutputDebugString("NtTerminateProcess hook: Dumped disguised PE payload.");
                }                
                else
                {
                    AllocationDumped = DumpMemory(AllocationBase, AllocationSize);

                    if (!AllocationDumped)
                    {
                        DoOutputDebugString("NtTerminateProcess hook: failed to dump memory range at 0x%x.\n", AllocationBase);
                    }
                    else
                    {
                        DoOutputDebugString("NtTerminateProcess hook: successfully dumped memory range.\n");
                        ClearBreakpointsInRange(GetCurrentThreadId(), AllocationBase, AllocationSize);       
                    }
                }
            }
            else
            {
                DoOutputDebugString("NtTerminateProcess hook: CAPE ignoring region: 0x%x as it is empty.\n", AllocationBase);
                ExtractionClearAll();
            }
        }

		process_shutting_down = 1;
		LOQ_ntstatus("process", "ph", "ProcessHandle", ProcessHandle, "ExitCode", ExitStatus);
		pipe("KILL:%d", GetCurrentProcessId());
		log_free();
	}
	else {
		DWORD PID = pid_from_process_handle(ProcessHandle);
		if (is_protected_pid(PID)) {
			ret = STATUS_ACCESS_DENIED;
			LOQ_ntstatus("process", "ph", "ProcessHandle", ProcessHandle, "ExitCode", ExitStatus);
			return ret;
		}
		else {
			LOQ_ntstatus("process", "ph", "ProcessHandle", ProcessHandle, "ExitCode", ExitStatus);
		}
		pipe("KILL:%d", PID);
	}
	set_lasterrors(&lasterror);

	ret = Old_NtTerminateProcess(ProcessHandle, ExitStatus);
    return ret;
}

extern void file_write(HANDLE file_handle);

HOOKDEF(NTSTATUS, WINAPI, NtCreateSection,
    __out     PHANDLE SectionHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in_opt  POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt  PLARGE_INTEGER MaximumSize,
    __in      ULONG SectionPageProtection,
    __in      ULONG AllocationAttributes,
    __in_opt  HANDLE FileHandle
) {
    NTSTATUS ret = Old_NtCreateSection(SectionHandle, DesiredAccess,
        ObjectAttributes, MaximumSize, SectionPageProtection,
        AllocationAttributes, FileHandle);
    LOQ_ntstatus("process", "Phop", "SectionHandle", SectionHandle,
        "DesiredAccess", DesiredAccess, "ObjectAttributes", ObjectAttributes ? ObjectAttributes->ObjectName : NULL,
        "FileHandle", FileHandle);

	if (NT_SUCCESS(ret) && FileHandle && (DesiredAccess & SECTION_MAP_WRITE)) {
		file_write(FileHandle);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenSection,
    __out  PHANDLE SectionHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
) {
    NTSTATUS ret = Old_NtOpenSection(SectionHandle, DesiredAccess,
        ObjectAttributes);
    LOQ_ntstatus("process", "Ppo", "SectionHandle", SectionHandle, "DesiredAccess", DesiredAccess,
        "ObjectAttributes", ObjectAttributes ? ObjectAttributes->ObjectName : NULL);
    return ret;
}

HOOKDEF(BOOL, WINAPI, ShellExecuteExW,
    __inout  SHELLEXECUTEINFOW *pExecInfo
) {
    BOOL ret = Old_ShellExecuteExW(pExecInfo);
	if (pExecInfo->lpFile && lstrlenW(pExecInfo->lpFile) > 2 &&
		pExecInfo->lpFile[1] == L':' && pExecInfo->lpFile[2] == L'\\') {
		LOQ_bool("process", "Fui", "FilePath", pExecInfo->lpFile,
			"Parameters", pExecInfo->lpParameters, "Show", pExecInfo->nShow);
	} else {
		LOQ_bool("process", "uui", "FilePath", pExecInfo->lpFile,
			"Parameters", pExecInfo->lpParameters, "Show", pExecInfo->nShow);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtUnmapViewOfSection,
    _In_      HANDLE ProcessHandle,
    _In_opt_  PVOID BaseAddress
) {
    SIZE_T map_size = 0; MEMORY_BASIC_INFORMATION mbi;
	DWORD pid = pid_from_process_handle(ProcessHandle);
	NTSTATUS ret;

	if (VirtualQueryEx(ProcessHandle, BaseAddress, &mbi,
            sizeof(mbi)) == sizeof(mbi)) {
        map_size = mbi.RegionSize;
    }
    ret = Old_NtUnmapViewOfSection(ProcessHandle, BaseAddress);
	
    LOQ_ntstatus("process", "ppp", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
        "RegionSize", map_size);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtMapViewOfSection,
	_In_     HANDLE SectionHandle,
	_In_     HANDLE ProcessHandle,
	__inout  PVOID *BaseAddress,
	_In_     ULONG_PTR ZeroBits,
	_In_     SIZE_T CommitSize,
	__inout  PLARGE_INTEGER SectionOffset,
	__inout  PSIZE_T ViewSize,
	__in     UINT InheritDisposition,
	__in     ULONG AllocationType,
	__in     ULONG Win32Protect
	) {
	NTSTATUS ret = Old_NtMapViewOfSection(SectionHandle, ProcessHandle,
		BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize,
		InheritDisposition, AllocationType, Win32Protect);
	DWORD pid = pid_from_process_handle(ProcessHandle);
      
    LOQ_ntstatus("process", "ppPpPhs", "SectionHandle", SectionHandle,
    "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
    "SectionOffset", SectionOffset, "ViewSize", ViewSize, "Win32Protect", Win32Protect, "StackPivoted", is_stack_pivoted() ? "yes" : "no");

	if (NT_SUCCESS(ret)) {
		if (pid != GetCurrentProcessId()) {
			pipe("PROCESS:%d:%d", is_suspended(pid, 0), pid);
			disable_sleep_skip();
		}
	}
	return ret;
}

// it's not safe to call pipe() in this hook until we replace all uses of snprintf in pipe()
HOOKDEF(NTSTATUS, WINAPI, NtAllocateVirtualMemory,
    __in     HANDLE ProcessHandle,
    __inout  PVOID *BaseAddress,
    __in     ULONG_PTR ZeroBits,
    __inout  PSIZE_T RegionSize,
    __in     ULONG AllocationType,
    __in     ULONG Protect
) {
    PBYTE PEImage;
    PIMAGE_DOS_HEADER pDosHeader;
	LPCVOID PEPointer;
    MEMORY_BASIC_INFORMATION MemInfo;

    NTSTATUS ret = Old_NtAllocateVirtualMemory(ProcessHandle, BaseAddress,
        ZeroBits, RegionSize, AllocationType, Protect);

	if (NT_SUCCESS(ret) && !called_by_hook() && (Protect & (PAGE_EXECUTE_READWRITE)) && GetCurrentProcessId() == our_getprocessid(ProcessHandle) && (*RegionSize >= EXTRACTION_MIN_SIZE || *BaseAddress == AllocationBase)) {
        DoOutputDebugString("NtAllocateVirtualMemory hook, BaseAddress:0x%x, RegionSize: 0x%x.\n", *BaseAddress, *RegionSize);
        
        if (AllocationBase && AllocationSize && !AllocationDumped)
        {
            if (AllocationBaseWriteBpSet == FALSE && AllocationType & MEM_COMMIT && (*BaseAddress == AllocationBase))
            {   // if memory was previously reserved but not committed
                SetInitialWriteBreakpoint(AllocationBase, AllocationSize);
            }
            else
            {
                DoOutputDebugString("NtAllocateVirtualMemory hook: attempting CAPE dump on previous region: 0x%x.\n", AllocationBase);

                AllocationDumped = TRUE;
                PEPointer = NULL;
                memset(&MemInfo, 0, sizeof(MemInfo));
                VirtualQuery(AllocationBase, &MemInfo, sizeof(MemInfo));
                
                if (PeImageDetected || ScanForPE(MemInfo.AllocationBase, MemInfo.RegionSize, &PEPointer))
                {
                    if (PEPointer)
                    {
                        DoOutputDebugString("NtAllocateVirtualMemory hook: PE image found in scan at: 0x%x.\n", PEPointer);
                        AllocationDumped = DumpImageInCurrentProcess((DWORD)PEPointer);
                    }
                    else
                    {
                        DoOutputDebugString("NtAllocateVirtualMemory hook: Attempting dump of previously marked PE image at: 0x%x.\n", AllocationBase);
                        AllocationDumped = DumpImageInCurrentProcess((DWORD)AllocationBase);
                    }
                    
                    if (!AllocationDumped)
                    {
                        DoOutputErrorString("NtAllocateVirtualMemory hook: Previous attempting to dump PE image failed");
                        
                        AllocationDumped = TRUE;
                        AllocationDumped = DumpMemory(AllocationBase, AllocationSize);
                        
                        if (!AllocationDumped)
                        {
                            DoOutputDebugString("NtAllocateVirtualMemory hook: failed to dump memory range at 0x%x.\n", AllocationBase);
                        }
                        else
                        {
                            DoOutputDebugString("NtAllocateVirtualMemory hook: successfully dumped memory range.\n");
                        }
                    }
                    else
                    {
                        DoOutputDebugString("NtAllocateVirtualMemory hook: successfully dumped module at 0x%x.\n", AllocationBase);
                    }
                }
                else if (IsDisguisedPE(MemInfo.AllocationBase, MemInfo.RegionSize))
                {
                    // Fix the PE header in the dump
                    pDosHeader = (PIMAGE_DOS_HEADER)MemInfo.AllocationBase;
                    PEImage = (BYTE*)malloc(MemInfo.RegionSize);
                    memcpy(PEImage, MemInfo.AllocationBase, MemInfo.RegionSize);

                    *(WORD*)PEImage = IMAGE_DOS_SIGNATURE;
                    *(DWORD*)(PEImage + pDosHeader->e_lfanew) = IMAGE_NT_SIGNATURE;

                    DumpImageInCurrentProcess((DWORD)PEImage);
                    
                    free(PEImage);

                    DoOutputDebugString("NtTerminateProcess hook: Dumped disguised PE payload.");
                }                
                else if (ScanForNonZero(AllocationBase, AllocationSize))
                {
                    DoOutputDebugString("NtAllocateVirtualMemory hook: No PE detected, attempting raw dump of memory image at: 0x%x.\n", AllocationBase);
                    
                    AllocationDumped = DumpMemory(AllocationBase, AllocationSize);

                    if (!AllocationDumped)
                    {
                        DoOutputDebugString("NtAllocateVirtualMemory hook: failed to dump memory range.\n");
                    }
                    else
                    {
                        DoOutputDebugString("NtAllocateVirtualMemory hook: successfully dumped memory range.\n");
                    }
                }
                else
                {
                    DoOutputDebugString("NtAllocateVirtualMemory hook: Previously marked memory range at: 0x%x is empty or inaccessible.\n", AllocationBase);
                    ExtractionClearAll();
                }
                
                // set breakpoints on new region
                if (AllocationType & MEM_COMMIT)
                    // Allocation committed, we set an initial write bp
                    SetInitialWriteBreakpoint(*BaseAddress, *RegionSize);
                else if (AllocationType & MEM_RESERVE)
                {   // Allocation not committed, so we can't set a bp yet
                    AllocationBaseWriteBpSet = FALSE;
                    AllocationBase = *BaseAddress;
                    AllocationSize = *RegionSize;
                    DoOutputDebugString("NtAllocateVirtualMemory hook: Memory reserved but not committed at 0x%x.\n", AllocationBase);
                }
            }
        }
        else if (AllocationType & MEM_COMMIT)
            // Allocation committed, we set an initial write bp
            SetInitialWriteBreakpoint(*BaseAddress, *RegionSize);
        else if (AllocationType & MEM_RESERVE)
        {   // Allocation not committed, so we can't set a bp yet
            AllocationBaseWriteBpSet = FALSE;
            AllocationBase = *BaseAddress;
            AllocationSize = *RegionSize;
            DoOutputDebugString("NtAllocateVirtualMemory hook: Memory reserved but not committed at 0x%x.\n", AllocationBase);
        }
    }
    
	if (ret != STATUS_CONFLICTING_ADDRESSES) {
		LOQ_ntstatus("process", "pPPhs", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"RegionSize", RegionSize, "Protection", Protect, "StackPivoted", is_stack_pivoted() ? "yes" : "no");
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtReadVirtualMemory,
    __in        HANDLE ProcessHandle,
    __in        LPCVOID BaseAddress,
    __out       LPVOID Buffer,
    __in        SIZE_T NumberOfBytesToRead,
    __out_opt   PSIZE_T NumberOfBytesRead
) {
	NTSTATUS ret;
    ENSURE_SIZET(NumberOfBytesRead);

    ret = Old_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer,
        NumberOfBytesToRead, NumberOfBytesRead);

    LOQ_ntstatus("process", "ppB", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
        "Buffer", NumberOfBytesRead, Buffer);

	return ret;
}

HOOKDEF(BOOL, WINAPI, ReadProcessMemory,
    _In_    HANDLE hProcess,
    _In_    LPCVOID lpBaseAddress,
    _Out_   LPVOID lpBuffer,
    _In_    SIZE_T nSize,
    _Out_   PSIZE_T lpNumberOfBytesRead
) {
    BOOL ret;
    ENSURE_SIZET(lpNumberOfBytesRead);

    ret = Old_ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer,
        nSize, lpNumberOfBytesRead);

    LOQ_bool("process", "ppB", "ProcessHandle", hProcess, "BaseAddress", lpBaseAddress,
        "Buffer", lpNumberOfBytesRead, lpBuffer);

    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtWriteVirtualMemory,
    __in        HANDLE ProcessHandle,
    __in        LPVOID BaseAddress,
    __in        LPCVOID Buffer,
    __in        SIZE_T NumberOfBytesToWrite,
    __out_opt   PSIZE_T NumberOfBytesWritten
) {
	NTSTATUS ret;
	DWORD pid;
    ENSURE_SIZET(NumberOfBytesWritten);

    ret = Old_NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
        NumberOfBytesToWrite, NumberOfBytesWritten);

	pid = pid_from_process_handle(ProcessHandle);

    LOQ_ntstatus("process", "ppBhs", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
        "Buffer", NumberOfBytesWritten, Buffer, "BufferLength", *NumberOfBytesWritten, "StackPivoted", is_stack_pivoted() ? "yes" : "no");

	if (pid != GetCurrentProcessId()) {
		if (NT_SUCCESS(ret)) {
			pipe("PROCESS:%d:%d", is_suspended(pid, 0), pid);
			disable_sleep_skip();
		}
	}


	return ret;
}

HOOKDEF(BOOL, WINAPI, WriteProcessMemory,
    _In_    HANDLE hProcess,
    _In_    LPVOID lpBaseAddress,
    _In_    LPCVOID lpBuffer,
    _In_    SIZE_T nSize,
    _Out_   PSIZE_T lpNumberOfBytesWritten
) {
	BOOL ret;
	DWORD pid;
    ENSURE_SIZET(lpNumberOfBytesWritten);

    ret = Old_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer,
        nSize, lpNumberOfBytesWritten);

	pid = pid_from_process_handle(hProcess);

    LOQ_bool("process", "ppBhs", "ProcessHandle", hProcess, "BaseAddress", lpBaseAddress,
        "Buffer", lpNumberOfBytesWritten, lpBuffer, "BufferLength", *lpNumberOfBytesWritten, "StackPivoted", is_stack_pivoted() ? "yes" : "no");

	if (pid != GetCurrentProcessId()) {
		if (ret) {
			pipe("PROCESS:%d:%d", is_suspended(pid, 0), pid);
			disable_sleep_skip();
		}
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtWow64ReadVirtualMemory64,
	__in HANDLE ProcessHandle,
	__in_opt LARGE_INTEGER BaseAddress,
	__out PVOID Buffer,
	__in LARGE_INTEGER BufferSize,
	__out_opt PLARGE_INTEGER NumberOfBytesRead
) {
	NTSTATUS ret;
	DWORD pid;
	ENSURE_LARGE_INTEGER(NumberOfBytesRead);

	ret = Old_NtWow64ReadVirtualMemory64(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);

	pid = pid_from_process_handle(ProcessHandle);

	LOQ_ntstatus("process", "pxb", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
		"Buffer", NumberOfBytesRead->LowPart, Buffer);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtWow64WriteVirtualMemory64,
	__in HANDLE ProcessHandle,
	__in_opt LARGE_INTEGER BaseAddress,
	__in PVOID Buffer,
	__in LARGE_INTEGER BufferSize,
	__out_opt PLARGE_INTEGER NumberOfBytesWritten
) {
	BOOL ret;
	DWORD pid;
	ENSURE_LARGE_INTEGER(NumberOfBytesWritten);

	ret = Old_NtWow64WriteVirtualMemory64(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);

	pid = pid_from_process_handle(ProcessHandle);

    LOQ_bool("process", "pxbhs", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
        "Buffer", NumberOfBytesWritten->LowPart, Buffer, "BufferLength", NumberOfBytesWritten->LowPart, "StackPivoted", is_stack_pivoted() ? "yes" : "no");

	if (pid != GetCurrentProcessId()) {
		if (ret) {
			pipe("PROCESS:%d:%d", is_suspended(pid, 0), pid);
			disable_sleep_skip();
		}
	}

	return ret;
}

/* need to keep in mind we might end up being called in either of the two below functions while some
   critical DLL code is protected RW by some poorly-written malware that doesn't care about reliability with
   concurrent thread execution
 */
HOOKDEF(NTSTATUS, WINAPI, NtProtectVirtualMemory,
    IN      HANDLE ProcessHandle,
    IN OUT  PVOID *BaseAddress,
    IN OUT  PSIZE_T NumberOfBytesToProtect,
    IN      ULONG NewAccessProtection,
    OUT     PULONG OldAccessProtection
) {
	NTSTATUS ret;
	MEMORY_BASIC_INFORMATION meminfo;
	LPCVOID PEPointer;
	int Register;



	if (NewAccessProtection == PAGE_EXECUTE_READ && BaseAddress && NumberOfBytesToProtect &&
		GetCurrentProcessId() == our_getprocessid(ProcessHandle) && is_in_dll_range((ULONG_PTR)*BaseAddress))
		restore_hooks_on_range((ULONG_PTR)*BaseAddress, (ULONG_PTR)*BaseAddress + *NumberOfBytesToProtect);
	
	ret = Old_NtProtectVirtualMemory(ProcessHandle, BaseAddress,
        NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);

	memset(&meminfo, 0, sizeof(meminfo));
	if (NT_SUCCESS(ret)) {
		lasterror_t lasterrors;
		get_lasterrors(&lasterrors);
		VirtualQueryEx(ProcessHandle, *BaseAddress, &meminfo, sizeof(meminfo));
		set_lasterrors(&lasterrors);
	}

	if (NT_SUCCESS(ret) && !called_by_hook() && (NewAccessProtection & (PAGE_EXECUTE |PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)) && GetCurrentProcessId() == our_getprocessid(ProcessHandle) && *NumberOfBytesToProtect >= EXTRACTION_MIN_SIZE) {
        DoOutputDebugString("NtProtectVirtualMemory hook: BaseAddress:0x%x, NumberOfBytesToProtect: 0x%x, NewAccessProtection: 0x%x\n", *BaseAddress, *NumberOfBytesToProtect, NewAccessProtection);
        if (AllocationBase == 0)    
        {
            if (*BaseAddress == meminfo.BaseAddress)
            {
                // we check if the buffer has already been written to 
                if (ScanForNonZero(*BaseAddress, *NumberOfBytesToProtect))
                {
                    if (SetNextAvailableBreakpoint(GetCurrentThreadId(), &Register, 0, (BYTE*)*BaseAddress, BP_EXEC, MidPageExecCallback))
                    {
                        AllocationBaseExecBpSet = TRUE;
                        AllocationBase = *BaseAddress;
                        DoOutputDebugString("NtProtectVirtualMemory hook: Execution breakpoint %d set base address: 0x%x, AllocationBaseExecBpSet = %d\n", Register, *BaseAddress, AllocationBaseExecBpSet);
                    }
                    else
                    {
                        DoOutputDebugString("NtProtectVirtualMemory hook: SetNextAvailableBreakpoint failed to set exec bp on allocation base.\n");
                        return FALSE;
                    }
                }
                else    // looks like it's still an empty buffer
                {
                    DoOutputDebugString("NtProtectVirtualMemory hook: Setting initial write breakpoint on protection address: 0x%x\n", *BaseAddress);
                    SetInitialWriteBreakpoint(*BaseAddress, *NumberOfBytesToProtect);
                }
            }
            else
            {
                DoOutputDebugString("NtProtectVirtualMemory hook: Setting mid-page exec breakpoint on protection address: 0x%x\n", *BaseAddress);
                SetMidPageBreakpoint(*BaseAddress, *NumberOfBytesToProtect);             
            }
        }
        else if (AllocationWriteDetected && AllocationBase && AllocationSize && !AllocationDumped)
        {
            DoOutputDebugString("NtProtectVirtualMemory hook: attempting CAPE dump on region: 0x%x.\n", AllocationBase);

            AllocationDumped = TRUE;
            PEPointer = NULL;
            memset(&meminfo, 0, sizeof(meminfo));
            VirtualQuery(AllocationBase, &meminfo, sizeof(meminfo));
                
            if (PeImageDetected || ScanForPE(meminfo.AllocationBase, meminfo.RegionSize, &PEPointer))            
            {
                if (PEPointer)
                    AllocationDumped = DumpImageInCurrentProcess((DWORD)PEPointer);
                else
                    AllocationDumped = DumpImageInCurrentProcess((DWORD)AllocationBase);
                
                if (!AllocationDumped)
                {
                    AllocationDumped = TRUE;
                    AllocationDumped = DumpMemory(AllocationBase, AllocationSize);
                    
                    if (!AllocationDumped)
                    {
                        DoOutputDebugString("NtProtectVirtualMemory hook: failed to dump memory range at 0x%x.\n", AllocationBase);
                    }
                    else
                    {
                        DoOutputDebugString("NtProtectVirtualMemory hook: successfully dumped memory range at 0x%x.\n", AllocationBase);
                    }
                }
                else
                {
                    DoOutputDebugString("NtProtectVirtualMemory hook: successfully dumped module at 0x%x.\n", AllocationBase);
                }
            }
            else
            {
                AllocationDumped = DumpMemory(AllocationBase, AllocationSize);

                if (!AllocationDumped)
                {
                    DoOutputDebugString("NtProtectVirtualMemory hook: failed to dump memory range at 0x%x.\n", AllocationBase);
                }
                else
                {
                    DoOutputDebugString("NtProtectVirtualMemory hook: successfully dumped memory range at 0x%x.\n", AllocationBase);
                }
            }
            
            if ((DWORD)*BaseAddress < (DWORD)AllocationBase && (DWORD)*BaseAddress >= ((DWORD)AllocationBase + AllocationSize))
            {
                // we check if the buffer has already been written to 
                if (ScanForNonZero(*BaseAddress, *NumberOfBytesToProtect))
                {
                    if (SetNextAvailableBreakpoint(GetCurrentThreadId(), &Register, 0, (BYTE*)*BaseAddress, BP_EXEC, MidPageExecCallback))
                    {
                        AllocationBaseExecBpSet = TRUE;
                        AllocationBase = *BaseAddress;
                        AllocationSize = *NumberOfBytesToProtect;
                        DoOutputDebugString("NtProtectVirtualMemory hook: Execution breakpoint %d set base address: 0x%x, AllocationBaseExecBpSet = %d\n", Register, *BaseAddress, AllocationBaseExecBpSet);
                    }
                    else
                    {
                        DoOutputDebugString("NtProtectVirtualMemory hook: SetNextAvailableBreakpoint failed to set exec bp on allocation base.\n");
                        return FALSE;
                    }
                }
                else    // looks like it's still an empty buffer
                {
                    DoOutputDebugString("NtProtectVirtualMemory hook: Setting initial write breakpoint on protection address: 0x%x\n", *BaseAddress);
                    SetInitialWriteBreakpoint(*BaseAddress, *NumberOfBytesToProtect);
                }            
            }
        }
    }

	if (NewAccessProtection == PAGE_EXECUTE_READWRITE && GetCurrentProcessId() == our_getprocessid(ProcessHandle) &&
		(ULONG_PTR)meminfo.AllocationBase >= get_stack_bottom() && (((ULONG_PTR)meminfo.AllocationBase + meminfo.RegionSize) <= get_stack_top())) {
		LOQ_ntstatus("process", "pPPhhHss", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"NumberOfBytesProtected", NumberOfBytesToProtect,
			"MemoryType", meminfo.Type,
			"NewAccessProtection", NewAccessProtection,
			"OldAccessProtection", OldAccessProtection, "StackPivoted", is_stack_pivoted() ? "yes" : "no", "IsStack", "yes");
	}
	else {
		LOQ_ntstatus("process", "pPPhhHs", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"NumberOfBytesProtected", NumberOfBytesToProtect,
			"MemoryType", meminfo.Type,
			"NewAccessProtection", NewAccessProtection,
			"OldAccessProtection", OldAccessProtection, "StackPivoted", is_stack_pivoted() ? "yes" : "no");
	}
    return ret;
}

HOOKDEF(BOOL, WINAPI, VirtualProtectEx,
    __in   HANDLE hProcess,
    __in   LPVOID lpAddress,
    __in   SIZE_T dwSize,
    __in   DWORD flNewProtect,
    __out  PDWORD lpflOldProtect
) {
	BOOL ret;
	MEMORY_BASIC_INFORMATION meminfo;
	LPCVOID PEPointer;
    int Register;

	if (flNewProtect == PAGE_EXECUTE_READ && GetCurrentProcessId() == our_getprocessid(hProcess) &&
		is_in_dll_range((ULONG_PTR)lpAddress))
		restore_hooks_on_range((ULONG_PTR)lpAddress, (ULONG_PTR)lpAddress + dwSize);

	ret = Old_VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect,
        lpflOldProtect);

	memset(&meminfo, 0, sizeof(meminfo));
	if (ret) {
		lasterror_t lasterrors;
		get_lasterrors(&lasterrors);
		VirtualQueryEx(hProcess, lpAddress, &meminfo, sizeof(meminfo));
		set_lasterrors(&lasterrors);
	}

	if (NT_SUCCESS(ret) && !called_by_hook() && (flNewProtect & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)) && GetCurrentProcessId() == our_getprocessid(hProcess) && dwSize >= EXTRACTION_MIN_SIZE) {
    
        DoOutputDebugString("VirtualProtectEx hook, lpAddress:0x%x, dwSize: 0x%x\n", lpAddress, dwSize);
        
        if (AllocationBase == 0)    
        {
            if (lpAddress == meminfo.BaseAddress)
            {
                // we check if the buffer has already been written to 
                if (ScanForNonZero(lpAddress, dwSize))
                {
                    if (ScanForPE(meminfo.AllocationBase, meminfo.RegionSize, &PEPointer))
                    {
                        //SetCapeMetaData(EXTRACTION_PE, 0, NULL, PEPointer);
                        DoOutputDebugString("VirtualProtectEx hook: Found a PE image.\n");

                        if (DumpImageInCurrentProcess((DWORD)PEPointer))
                        {
                            DoOutputDebugString("VirtualProtectEx hook: Found and dumped a PE image.\n");
                        }
                        else
                        {
                            DoOutputDebugString("VirtualProtectEx hook: Found a PE image but failed to dump it.\n");
                        }                    
                    }
                    else if (SetNextAvailableBreakpoint(GetCurrentThreadId(), &Register, 0, (BYTE*)lpAddress, BP_EXEC, MidPageExecCallback))
                    {
                        AllocationBaseExecBpSet = TRUE;
                        AllocationBase = lpAddress;
                        AllocationSize = dwSize;
                        DoOutputDebugString("VirtualProtectEx hook: Execution breakpoint %d set base address: 0x%x, AllocationBaseExecBpSet = %d\n", Register, lpAddress, AllocationBaseExecBpSet);
                    }
                    else
                    {
                        DoOutputDebugString("VirtualProtectEx hook: SetNextAvailableBreakpoint failed to set exec bp on allocation base.\n");
                        return FALSE;
                    }
                }
                else    // looks like it's still an empty buffer
                {
                    DoOutputDebugString("VirtualProtectEx hook: Setting initial write breakpoint on protection address: 0x%x\n", lpAddress);
                    SetInitialWriteBreakpoint(lpAddress, dwSize);
                }
            }
            else
            {
                DoOutputDebugString("VirtualProtectEx hook: Setting mid-page exec breakpoint on protection address: 0x%x\n", lpAddress);
                SetMidPageBreakpoint(lpAddress, dwSize);             
            }
        }
        else if (AllocationWriteDetected && AllocationBase && AllocationSize && !AllocationDumped)
        {
            DoOutputDebugString("VirtualProtectEx hook: attempting CAPE dump on region: 0x%x.\n", AllocationBase);

            AllocationDumped = TRUE;
            PEPointer = NULL;
            memset(&meminfo, 0, sizeof(meminfo));
            VirtualQuery(AllocationBase, &meminfo, sizeof(meminfo));
            
            if (PeImageDetected || ScanForPE(meminfo.AllocationBase, meminfo.RegionSize, &PEPointer))
            {
                if (PEPointer)
                    AllocationDumped = DumpImageInCurrentProcess((DWORD)PEPointer);
                else
                    AllocationDumped = DumpImageInCurrentProcess((DWORD)AllocationBase);
                
                if (!AllocationDumped)
                {
                    AllocationDumped = TRUE;
                    AllocationDumped = DumpMemory(AllocationBase, AllocationSize);
                    
                    if (!AllocationDumped)
                    {
                        DoOutputDebugString("VirtualProtectEx hook: failed to dump memory range at 0x%x.\n", AllocationBase);
                    }
                    else
                    {
                        DoOutputDebugString("VirtualProtectEx hook: successfully dumped memory range at 0x%x.\n", AllocationBase);
                        ClearBreakpointsInRange(GetCurrentThreadId(), AllocationBase, AllocationSize);       
                    }
                }
                else
                {
                    DoOutputDebugString("VirtualProtectEx hook: successfully dumped module.\n");
                    ClearBreakpointsInRange(GetCurrentThreadId(), AllocationBase, AllocationSize);       
                }
            }
            else
            {
                AllocationDumped = DumpMemory(AllocationBase, AllocationSize);

                if (!AllocationDumped)
                {
                    DoOutputDebugString("VirtualProtectEx hook: failed to dump memory range at 0x%x.\n", AllocationBase);
                }
                else
                {
                    DoOutputDebugString("VirtualProtectEx hook: successfully dumped memory range at 0x%x.\n", AllocationBase);
                    ClearBreakpointsInRange(GetCurrentThreadId(), AllocationBase, AllocationSize);       
                }
            }
            
            if ((DWORD)lpAddress < (DWORD)AllocationBase && (DWORD)lpAddress >= ((DWORD)AllocationBase + AllocationSize))
            {
                // we check if the buffer has already been written to 
                if (ScanForNonZero(lpAddress, dwSize))
                {
                    if (ScanForNonZero(meminfo.AllocationBase, (BYTE*)AllocationBase + AllocationSize - (BYTE*)meminfo.AllocationBase)
                            && ScanForPE(meminfo.AllocationBase, (BYTE*)AllocationBase + AllocationSize - (BYTE*)meminfo.AllocationBase, &PEPointer))
                    {
                        SetCapeMetaData(EXTRACTION_PE, 0, NULL, (PVOID)PEPointer);

                        if (DumpImageInCurrentProcess((DWORD)PEPointer))
                        {
                            DoOutputDebugString("VirtualProtectEx hook: Found and dumped a PE image.\n");
                        }
                        else
                        {
                            DoOutputDebugString("VirtualProtectEx hook: Found a PE image but failed to dump it.\n");
                        }
                    }
                    else  if (SetNextAvailableBreakpoint(GetCurrentThreadId(), &Register, 0, (BYTE*)lpAddress, BP_EXEC, MidPageExecCallback))
                    {
                        AllocationBaseExecBpSet = TRUE;
                        AllocationBase = lpAddress;
                        AllocationSize = dwSize;
                        DoOutputDebugString("VirtualProtectEx hook: Execution breakpoint %d set base address: 0x%x, AllocationBaseExecBpSet = %d\n", Register, lpAddress, AllocationBaseExecBpSet);
                    }
                    else
                    {
                        DoOutputDebugString("VirtualProtectEx hook: SetNextAvailableBreakpoint failed to set exec bp on allocation base.\n");
                        return FALSE;
                    }
                }
                else    // looks like it's still an empty buffer
                {
                    DoOutputDebugString("VirtualProtectEx hook: Setting initial write breakpoint on protection address: 0x%x\n", lpAddress);

                    SetInitialWriteBreakpoint(lpAddress, dwSize);
                }            
            }
        }
    }

	if (flNewProtect == PAGE_EXECUTE_READWRITE && GetCurrentProcessId() == our_getprocessid(hProcess) &&
		(ULONG_PTR)meminfo.AllocationBase >= get_stack_bottom() && (((ULONG_PTR)meminfo.AllocationBase + meminfo.RegionSize) <= get_stack_top())) {
		LOQ_bool("process", "ppphhHss", "ProcessHandle", hProcess, "Address", lpAddress,
			"Size", dwSize, "MemType", meminfo.Type, "Protection", flNewProtect, "OldProtection", lpflOldProtect, "StackPivoted", is_stack_pivoted() ? "yes" : "no", "IsStack", "yes");
	}
	else {
		LOQ_bool("process", "ppphhHs", "ProcessHandle", hProcess, "Address", lpAddress,
			"Size", dwSize, "MemType", meminfo.Type, "Protection", flNewProtect, "OldProtection", lpflOldProtect, "StackPivoted", is_stack_pivoted() ? "yes" : "no");
	}
    return ret;
}

// it's not safe to call pipe() in this hook until we replace all uses of snprintf in pipe()
HOOKDEF(NTSTATUS, WINAPI, NtFreeVirtualMemory,
    IN      HANDLE ProcessHandle,
    IN      PVOID *BaseAddress,
    IN OUT  PSIZE_T RegionSize,
    IN      ULONG FreeType
) {
    NTSTATUS ret = Old_NtFreeVirtualMemory(ProcessHandle, BaseAddress,
        RegionSize, FreeType);

	if (NT_SUCCESS(ret) && !called_by_hook() && GetCurrentProcessId() == our_getprocessid(ProcessHandle) && *BaseAddress == AllocationBase) {
		DoOutputDebugString("NtFreeVirtualMemory hook: Clearing breakpoints in range 0x%x - 0x%x.\n", *BaseAddress, (char*)*BaseAddress + *RegionSize);
        ExtractionClearAll();
    }
        
    LOQ_ntstatus("process", "pPPh", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
        "RegionSize", RegionSize, "FreeType", FreeType);

	return ret;
}

HOOKDEF(BOOL, WINAPI, VirtualFreeEx,
    __in  HANDLE hProcess,
    __in  LPVOID lpAddress,
    __in  SIZE_T dwSize,
    __in  DWORD dwFreeType
) {
    BOOL ret = Old_VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);
    LOQ_bool("process", "ppph", "ProcessHandle", hProcess, "Address", lpAddress,
        "Size", dwSize, "FreeType", dwFreeType);
    return ret;
}

HOOKDEF(int, CDECL, system,
    const char *command
) {
    int ret = Old_system(command);
    LOQ_nonnegone("process", "s", "Command", command);
    return ret;
}

HOOKDEF(BOOL, WINAPI, WaitForDebugEvent,
	__out LPDEBUG_EVENT lpDebugEvent,
	__in DWORD dwMilliseconds
) {
	BOOL ret = Old_WaitForDebugEvent(lpDebugEvent, dwMilliseconds);

	if (!ret)
		return ret;

	switch (lpDebugEvent->dwDebugEventCode) {
	case CREATE_THREAD_DEBUG_EVENT:
		LOQ_bool("process", "iiip", "EventCode", lpDebugEvent->dwDebugEventCode, "ProcessId", lpDebugEvent->dwProcessId, "ThreadId", lpDebugEvent->dwThreadId, "StartAddress", lpDebugEvent->u.CreateThread.lpStartAddress);
		break;
	case LOAD_DLL_DEBUG_EVENT:
		// we could continue ourselves here and skip notification to the malware of cuckoomon loading
	default:
		LOQ_bool("process", "iii", "EventCode", lpDebugEvent->dwDebugEventCode, "ProcessId", lpDebugEvent->dwProcessId, "ThreadId", lpDebugEvent->dwThreadId);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, DbgUiWaitStateChange,
	__out PDBGUI_WAIT_STATE_CHANGE StateChange,
	__in_opt PLARGE_INTEGER Timeout)
{
	NTSTATUS ret = Old_DbgUiWaitStateChange(StateChange, Timeout);

	if (NT_SUCCESS(ret)) {
		switch (StateChange->NewState) {
		case DbgCreateThreadStateChange:
			LOQ_ntstatus("process", "iiip", "NewState", StateChange->NewState, "ProcessId", pid_from_process_handle(StateChange->AppClientId.UniqueProcess), "ThreadId", tid_from_thread_handle(StateChange->AppClientId.UniqueThread), "StartAddress", StateChange->StateInfo.CreateThread.NewThread.StartAddress);
			break;
		case DbgLoadDllStateChange:
			{
				wchar_t *fname = calloc(32768, sizeof(wchar_t));

				path_from_handle(StateChange->StateInfo.LoadDll.FileHandle, fname, 32768);
				// we could continue ourselves here and skip notification to the malware of cuckoomon loading
				LOQ_ntstatus("process", "iiiF", "NewState", StateChange->NewState, "ProcessId", pid_from_process_handle(StateChange->AppClientId.UniqueProcess), "ThreadId", tid_from_thread_handle(StateChange->AppClientId.UniqueThread), "DllPath", fname);
				free(fname);
			}
			break;
		default:
			LOQ_ntstatus("process", "iii", "NewState", StateChange->NewState, "ProcessId", pid_from_process_handle(StateChange->AppClientId.UniqueProcess), "ThreadId", tid_from_thread_handle(StateChange->AppClientId.UniqueThread));
		}
	}

	return ret;
}

HOOKDEF_NOTAIL(WINAPI, RtlDispatchException,
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in PCONTEXT Context)
{
#ifndef _WIN64
	if (ExceptionRecord && (ULONG_PTR)ExceptionRecord->ExceptionAddress >= g_our_dll_base && (ULONG_PTR)ExceptionRecord->ExceptionAddress < (g_our_dll_base + g_our_dll_size)) {
		char buf[160];
		ULONG_PTR seh = 0;
		DWORD *tebtmp = (DWORD *)NtCurrentTeb();
		if (tebtmp[0] != 0xffffffff)
			seh = ((DWORD *)tebtmp[0])[1];
		if (seh < g_our_dll_base || seh >= (g_our_dll_base + g_our_dll_size)) {
			_snprintf(buf, sizeof(buf), "Exception reported at offset 0x%x in cuckoomon itself while accessing 0x%x from hook %s", (DWORD)((ULONG_PTR)ExceptionRecord->ExceptionAddress - g_our_dll_base), ExceptionRecord->ExceptionInformation[1], hook_info()->current_hook ? hook_info()->current_hook->funcname : "unknown");
			log_anomaly("cuckoocrash", buf);
		}
	}
#endif

	// flush logs prior to handling of an exception without having to register a vectored exception handler
	log_flush();

	return 0;
}

HOOKDEF_NOTAIL(WINAPI, NtRaiseException,
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in PCONTEXT Context,
	__in BOOLEAN SearchFrames
) {
	EXCEPTION_POINTERS exc;

	exc.ContextRecord = Context;
	exc.ExceptionRecord = ExceptionRecord;

	if (g_config.debug)
		cuckoomon_exception_handler(&exc);

	return 0;
}

HOOKDEF(HANDLE, WINAPI, GetProcessHeap,
	void
) {
	HANDLE ret = Old_GetProcessHeap();

	LOQ_handle("process", "");//, "Handle", ret);

	return ret;
}

HOOKDEF(LPVOID, WINAPI, HeapAlloc,
  HANDLE hHeap,
  DWORD  dwFlags,
  SIZE_T dwBytes
) {
    LPVOID ret = Old_HeapAlloc(hHeap, dwFlags, dwBytes);
    
    //LOQ_nonnull("process", "phh", "HeapHandle", hHeap, "Flags", dwFlags, "Size", dwBytes);
    
    return ret;
}
