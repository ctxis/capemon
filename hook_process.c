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
#include <psapi.h>
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include "ignore.h"
#include "hook_sleep.h"
#include "unhook.h"
#include "config.h"
#include "CAPE\CAPE.h"

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);
extern int DumpMemory(LPVOID Buffer, SIZE_T Size);
extern int DumpImageInCurrentProcess(DWORD_PTR ImageBase);
extern int ScanForPE(LPVOID Buffer, unsigned int Size, LPVOID* Offset);

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

	NTSTATUS ret;
	struct InjectionInfo *CurrentInjectionInfo;
    DWORD BufferSize = MAX_PATH;
    char DevicePath[MAX_PATH];
    unsigned int PathLength;
    int pid = 0;

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
        
    if (NT_SUCCESS(ret)){// && (DesiredAccess & (PROCESS_CREATE_THREAD|PROCESS_VM_WRITE|PROCESS_SUSPEND_RESUME))){
        CurrentInjectionInfo = GetInjectionInfo(pid);
        
        if (CurrentInjectionInfo == NULL)
        {   // First call for this process, create new info
            CurrentInjectionInfo = CreateInjectionInfo(pid);
            DoOutputDebugString("NtOpenProcess: Injection info created for pid %d.\n", pid);
        
            if (CurrentInjectionInfo == NULL)
            {
                DoOutputDebugString("NtOpenProcess: Cannot create new injection info - FATAL ERROR.\n");
            }
            else
            {
                CurrentInjectionInfo->ProcessHandle = *ProcessHandle;
                CurrentInjectionInfo->EntryPoint = (DWORD_PTR)NULL;
                CurrentInjectionInfo->ImageDumped = FALSE;
                CapeMetaData->TargetProcess = (char*)malloc(BufferSize);

                CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(*ProcessHandle);
                
                if (!CurrentInjectionInfo->ImageBase)
                    DoOutputDebugString("NtOpenProcess: Error obtaining target process image base for process %d (handle 0x%x).\n", pid, *ProcessHandle);
                else
                    DoOutputDebugString("NtOpenProcess: Image base for process %d (handle 0x%x): 0x%p.\n", pid, *ProcessHandle, CurrentInjectionInfo->ImageBase);
                
                PathLength = GetProcessImageFileName(*ProcessHandle, DevicePath, BufferSize);

                if (!PathLength)
                {
                    DoOutputErrorString("NtOpenProcess: Error obtaining target process name");
                    _snprintf(CapeMetaData->TargetProcess, BufferSize, "Error obtaining target process name");
                }
                else if (!TranslatePathFromDeviceToLetter(DevicePath, CapeMetaData->TargetProcess, &BufferSize)) 
                    DoOutputErrorString("NtOpenProcess: Error translating target process path");                
            }
        }
        else if (CurrentInjectionInfo->ImageBase == (DWORD_PTR)NULL)
        {
            CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(*ProcessHandle);
            
            if (CurrentInjectionInfo->ImageBase)
                DoOutputDebugString("NtOpenProcess: Image base for process %d (handle 0x%x): 0x%p.\n", pid, *ProcessHandle, CurrentInjectionInfo->ImageBase);
        }
    }    
        
    LOQ_ntstatus("process", "Phi", "ProcessHandle", ProcessHandle,
        "DesiredAccess", DesiredAccess,
        "ProcessIdentifier", pid);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtResumeProcess,
	__in  HANDLE ProcessHandle
) {
	NTSTATUS ret;
	struct InjectionInfo *CurrentInjectionInfo;

    DWORD pid = pid_from_process_handle(ProcessHandle);
	pipe("RESUME:%d", pid);

    CurrentInjectionInfo = GetInjectionInfo(pid);
    
    if (CurrentInjectionInfo)
    {
        if (CurrentInjectionInfo->ImageBase && CurrentInjectionInfo->WriteDetected && CurrentInjectionInfo->ImageDumped == FALSE)
        {
            SetCapeMetaData(INJECTION_PE, pid, ProcessHandle, NULL);
            
            DoOutputDebugString("NtResumeProcess hook: Dumping hollowed process %d, image base 0x%x.\n", pid, CurrentInjectionInfo->ImageBase);
            
            CurrentInjectionInfo->ImageDumped = DumpProcess(ProcessHandle, CurrentInjectionInfo->ImageBase);
            
            if (CurrentInjectionInfo->ImageDumped)
            {
                DoOutputDebugString("NtResumeProcess hook: Dumped PE image from buffer.\n");
            }
            else
                DoOutputDebugString("NtResumeProcess hook: Failed to dump PE image from buffer.\n");
        }

        DumpSectionViewsForPid(pid);
    }
    
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
    NTSTATUS ret = 0;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);
	if (ProcessHandle == NULL) {
		// we mark this here as this termination type will kill all threads but ours, including
		// the logging thread.  By setting this, we'll switch into a direct logging mode
		// for the subsequent call to NtTerminateProcess against our own process handle
		process_shutting_down = 1;
		LOQ_ntstatus("process", "ph", "ProcessHandle", ProcessHandle, "ExitCode", ExitStatus);
	}
	else if (GetCurrentProcessId() == our_getprocessid(ProcessHandle)) {
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
    PINJECTIONSECTIONVIEW CurrentSectionView; 
    SIZE_T map_size = 0; MEMORY_BASIC_INFORMATION mbi;
	DWORD pid = pid_from_process_handle(ProcessHandle);
	DWORD protect = PAGE_READWRITE;
	NTSTATUS ret;

	if (VirtualQueryEx(ProcessHandle, BaseAddress, &mbi,
            sizeof(mbi)) == sizeof(mbi)) {
        map_size = mbi.RegionSize;
		protect = mbi.Protect;
    }
        
    CurrentSectionView = SectionViewList;

    while (CurrentSectionView)
    {
        if (CurrentSectionView->LocalView == BaseAddress)
        {
            DoOutputDebugString("NtUnmapViewOfSection hook: Attempt to unmap view at 0x%p, faking.\n", BaseAddress);

            ret = STATUS_SUCCESS;

            LOQ_ntstatus("process", "ppp", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
                "RegionSize", map_size);
                
            return ret;
        }

        CurrentSectionView = CurrentSectionView->NextSectionView;
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
	struct InjectionInfo *CurrentInjectionInfo;
    struct InjectionSectionView *CurrentSectionViewInfo;
    char DevicePath[MAX_PATH];
    unsigned int PathLength;
    DWORD BufferSize = MAX_PATH;
	
    NTSTATUS ret = Old_NtMapViewOfSection(SectionHandle, ProcessHandle,
		BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize,
		InheritDisposition, AllocationType, Win32Protect);
	
    DWORD pid = pid_from_process_handle(ProcessHandle);
    
    CurrentInjectionInfo = GetInjectionInfo(pid);
    
    if (pid == GetCurrentProcessId())
    {
        PINJECTIONSECTIONVIEW CurrentSectionView = GetSectionView(SectionHandle);
        
        if (!CurrentSectionView)
        {
            AddSectionView(SectionHandle, *BaseAddress, *ViewSize);
            DoOutputDebugString("NtMapViewOfSection hook: Added section view with handle 0x%x and local view 0x%x to global list.\n", SectionHandle, *BaseAddress);
        }
        else
        {
            if (NT_SUCCESS(ret) && CurrentSectionView->LocalView != *BaseAddress)
            {
                CurrentSectionView->LocalView = *BaseAddress;
                CurrentSectionView->ViewSize = *ViewSize;
                DoOutputDebugString("NtMapViewOfSection hook: Updated local view to 0x%x for section view with handle 0x%x.\n", *BaseAddress, SectionHandle);
            }
        }
    }
    else if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == pid)
    {
        DoOutputDebugString("NtMapViewOfSection hook: Section view with handle 0x%x and target process %d.\n", SectionHandle, pid);
        
        CurrentSectionViewInfo = GetSectionView(SectionHandle);

        if (CurrentSectionViewInfo)
        {
	        CurrentSectionViewInfo->TargetProcessId = pid;
            DoOutputDebugString("NtMapViewOfSection hook: Added section view with handle 0x%x and to target process %d.\n", SectionHandle, pid);
        }
        else
        {
            DoOutputDebugString("NtMapViewOfSection hook: Error, section view with handle 0x%x and target process %d not found in global list.\n", SectionHandle, pid);
        }
    }    
    else if (!CurrentInjectionInfo && pid != GetCurrentProcessId())
    {
        CurrentInjectionInfo = CreateInjectionInfo(pid);
        
        DoOutputDebugString("NtMapViewOfSection hook: Injection info created for pid %d.\n", pid);
    
        if (CurrentInjectionInfo == NULL)
        {
            DoOutputDebugString("NtMapViewOfSection hook: Cannot create new injection info - FATAL ERROR.\n");
        }
        else
        {
            CurrentInjectionInfo->ProcessHandle = ProcessHandle;
            CurrentInjectionInfo->ProcessId = pid;
            CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(ProcessHandle);
            CurrentInjectionInfo->EntryPoint = (DWORD_PTR)NULL;
            CurrentInjectionInfo->ImageDumped = FALSE;
            CapeMetaData->TargetProcess = (char*)malloc(BufferSize);

            PathLength = GetProcessImageFileName(ProcessHandle, DevicePath, BufferSize);

            if (!PathLength)
            {
                DoOutputErrorString("NtMapViewOfSection hook: Error obtaining target process name");
                _snprintf(CapeMetaData->TargetProcess, BufferSize, "Error obtaining target process name");
            }
            else if (!TranslatePathFromDeviceToLetter(DevicePath, CapeMetaData->TargetProcess, &BufferSize)) 
                DoOutputErrorString("NtMapViewOfSection hook: Error translating target process path");
                
            CurrentSectionViewInfo = AddSectionView(SectionHandle, *BaseAddress, *ViewSize);

            if (CurrentSectionViewInfo)
            {
                CurrentSectionViewInfo->TargetProcessId = pid;
                DoOutputDebugString("NtMapViewOfSection hook: Added section view with handle 0x%x and to target process %d.\n", SectionHandle, pid);
            }
            else
                DoOutputDebugString("NtMapViewOfSection hook: Error, section view with handle 0x%x and target process %d not found in global list.\n", SectionHandle, pid);
        }
    }
    
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
    NTSTATUS ret = Old_NtAllocateVirtualMemory(ProcessHandle, BaseAddress,
        ZeroBits, RegionSize, AllocationType, Protect);

	if (ret != STATUS_CONFLICTING_ADDRESSES && (Protect != PAGE_READWRITE || GetCurrentProcessId() != our_getprocessid(ProcessHandle))) {
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

	if (pid_from_process_handle(ProcessHandle) != GetCurrentProcessId()) {
		LOQ_ntstatus("process", "ppB", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"Buffer", NumberOfBytesRead, Buffer);
	}

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

	if (pid_from_process_handle(hProcess) != GetCurrentProcessId()) {
		LOQ_bool("process", "ppB", "ProcessHandle", hProcess, "BaseAddress", lpBaseAddress,
			"Buffer", lpNumberOfBytesRead, lpBuffer);
	}

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
	struct InjectionInfo *CurrentInjectionInfo;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    ENSURE_SIZET(NumberOfBytesWritten);

    ret = Old_NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
        NumberOfBytesToWrite, NumberOfBytesWritten);

	pid = pid_from_process_handle(ProcessHandle);
        
    CurrentInjectionInfo = GetInjectionInfo(pid);
    
    if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == pid)
    {
        CurrentInjectionInfo->WriteDetected = TRUE;
        
        if (NT_SUCCESS(ret) && *NumberOfBytesWritten > 0)
        {
            // Check if we have a valid DOS and PE header at the beginning of Buffer
            if (*(WORD*)Buffer == IMAGE_DOS_SIGNATURE)
            {
                pDosHeader = (PIMAGE_DOS_HEADER)((char*)Buffer);
                
                if (pDosHeader->e_lfanew && (unsigned int)pDosHeader->e_lfanew < PE_HEADER_LIMIT)
                    pNtHeader = (PIMAGE_NT_HEADERS)((char*)Buffer + pDosHeader->e_lfanew);
                
                if (pNtHeader->Signature == IMAGE_NT_SIGNATURE && pNtHeader->FileHeader.Machine != 0 && pNtHeader->FileHeader.SizeOfOptionalHeader != 0)
                {
                    CurrentInjectionInfo->ImageBase = (DWORD_PTR)BaseAddress;
                    
                    DoOutputDebugString("NtWriteVirtualMemory hook: Executable binary injected into process %d (ImageBase 0x%x)\n", pid, CurrentInjectionInfo->ImageBase);

                    if (CurrentInjectionInfo->ImageDumped == FALSE)
                    {
                        SetCapeMetaData(INJECTION_PE, pid, ProcessHandle, NULL);
                        CurrentInjectionInfo->ImageDumped = DumpImageInCurrentProcess((DWORD_PTR)Buffer);
                        
                        if (CurrentInjectionInfo->ImageDumped)
                        {
                            CurrentInjectionInfo->BufferBase = (LPVOID)Buffer;
                            CurrentInjectionInfo->BufferSizeOfImage = pNtHeader->OptionalHeader.SizeOfImage;
                            DoOutputDebugString("NtWriteVirtualMemory hook: Dumped PE image from buffer at 0x%x, SizeOfImage 0x%x.\n", Buffer, CurrentInjectionInfo->BufferSizeOfImage);
                        }
                        else
                            DoOutputDebugString("NtWriteVirtualMemory hook: Failed to dump PE image from buffer.\n");
                    }                    
                }
                else
                {
                    DoOutputDebugString("NtWriteVirtualMemory hook: invalid PE file in buffer, attempting raw dump.\n");
                    
                    CapeMetaData->DumpType = INJECTION_SHELLCODE;
                    CapeMetaData->TargetPid = pid;
                    if (DumpMemory((LPVOID)Buffer, *NumberOfBytesWritten))
                        DoOutputDebugString("NtWriteVirtualMemory hook: Dumped malformed PE image from buffer.");
                    else
                        DoOutputDebugString("NtWriteVirtualMemory hook: Failed to dump malformed PE image from buffer.");                    
                }
            }
            else
            {   
                if (*NumberOfBytesWritten > 0x10)
                {
                    if (CurrentInjectionInfo->BufferBase && Buffer > CurrentInjectionInfo->BufferBase && 
                        Buffer < (LPVOID)((UINT_PTR)CurrentInjectionInfo->BufferBase + CurrentInjectionInfo->BufferSizeOfImage) && CurrentInjectionInfo->ImageDumped == TRUE)
                    {   
                        // Looks like a previously dumped PE image is being written a section at a time to the target process.
                        // We don't want to dump these writes.
                        DoOutputDebugString("NtWriteVirtualMemory hook: injection of section of PE image which has already been dumped.\n");
                    }
                    else
                    {
                        DoOutputDebugString("NtWriteVirtualMemory hook: Shellcode at 0x%x (size 0x%x) injected into process %d.\n", Buffer, *NumberOfBytesWritten, pid);
                    
                        // dump injected code to .bin file
                        CapeMetaData->DumpType = INJECTION_SHELLCODE;
                        CapeMetaData->TargetPid = pid;
                        if (DumpMemory((LPVOID)Buffer, *NumberOfBytesWritten))
                            DoOutputDebugString("NtWriteVirtualMemory hook: Dumped injected code from buffer.");
                        else
                            DoOutputDebugString("NtWriteVirtualMemory hook: Failed to dump injected code from buffer.");
                    }
                }
            }
        }
    }

	if (pid != GetCurrentProcessId()) {
		LOQ_ntstatus("process", "ppBhs", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"Buffer", NumberOfBytesWritten, Buffer, "BufferLength", *NumberOfBytesWritten, "StackPivoted", is_stack_pivoted() ? "yes" : "no");

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
	struct InjectionInfo *CurrentInjectionInfo;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    ENSURE_SIZET(lpNumberOfBytesWritten);

    ret = Old_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer,
        nSize, lpNumberOfBytesWritten);

    pid = pid_from_process_handle(hProcess);
    
    CurrentInjectionInfo = GetInjectionInfo(pid);

    if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == pid)
    {
        CurrentInjectionInfo->WriteDetected = TRUE;
        
        if ((unsigned int)((PUCHAR)CurrentInjectionInfo->StackPointer - (PUCHAR)lpBaseAddress) < 0x100)
        {
            PINJECTIONSECTIONVIEW CurrentSectionView = SectionViewList;
            
            DoOutputDebugString("WriteProcessMemory hook: Target address is stack of target process %d.\n", pid);
            
            while (CurrentSectionView)
            {
#ifdef _WIN64
                if (CurrentSectionView->SectionHandle == (HANDLE)(*((DWORD_PTR*)lpBuffer + 1)))
#else
                if (CurrentSectionView->SectionHandle == (HANDLE)(*((DWORD*)lpBuffer + 1)))
#endif
                {
                    CurrentSectionView->TargetProcessId = pid;
                    DoOutputDebugString("WriteProcessMemory hook: Section handle 0x%x written to stack of target process %d.\n", CurrentSectionView->SectionHandle, pid);
                }
                
                CurrentSectionView = CurrentSectionView->NextSectionView;
            }
        }
        
        if (NT_SUCCESS(ret) && *lpNumberOfBytesWritten > 0)
        {
            // Check if we have a valid DOS and PE header at the beginning of Buffer
            if (*(WORD*)lpBuffer == IMAGE_DOS_SIGNATURE)
            {
                pDosHeader = (PIMAGE_DOS_HEADER)((char*)lpBuffer);
                
                if (pDosHeader->e_lfanew && (unsigned int)pDosHeader->e_lfanew < PE_HEADER_LIMIT)
                    pNtHeader = (PIMAGE_NT_HEADERS)((char*)lpBuffer + pDosHeader->e_lfanew);
                
                if (pNtHeader->Signature == IMAGE_NT_SIGNATURE && pNtHeader->FileHeader.Machine != 0 && pNtHeader->FileHeader.SizeOfOptionalHeader != 0)
                {
                    CurrentInjectionInfo->ImageBase = (DWORD_PTR)lpBaseAddress;
                    
                    DoOutputDebugString("WriteProcessMemory hook: Executable binary injected into process %d (ImageBase 0x%x)\n", pid, CurrentInjectionInfo->ImageBase);

                    if (CurrentInjectionInfo->ImageDumped == FALSE)
                    {
                        SetCapeMetaData(INJECTION_PE, pid, hProcess, NULL);
                        CurrentInjectionInfo->ImageDumped = DumpImageInCurrentProcess((DWORD_PTR)lpBuffer);
                        
                        if (CurrentInjectionInfo->ImageDumped)
                        {
                            CurrentInjectionInfo->BufferBase = (LPVOID)lpBuffer;
                            CurrentInjectionInfo->BufferSizeOfImage = pNtHeader->OptionalHeader.SizeOfImage;
                            DoOutputDebugString("WriteProcessMemory hook: Dumped PE image from buffer at 0x%x, SizeOfImage 0x%x.\n", lpBuffer, CurrentInjectionInfo->BufferSizeOfImage);
                        }
                        else
                            DoOutputDebugString("WriteProcessMemory hook: Failed to dump PE image from buffer.\n");
                    }                    
                }
                else
                {
                    DoOutputDebugString("WriteProcessMemory hook: invalid PE file in buffer, attempting raw dump.\n");
                    
                    CapeMetaData->DumpType = INJECTION_SHELLCODE;
                    CapeMetaData->TargetPid = pid;
                    if (DumpMemory((LPVOID)lpBuffer, *lpNumberOfBytesWritten))
                        DoOutputDebugString("WriteProcessMemory hook: Dumped malformed PE image from buffer.");
                    else
                        DoOutputDebugString("WriteProcessMemory hook: Failed to dump malformed PE image from buffer.");                    
                }
            }
            else
            {   
                if (*lpNumberOfBytesWritten > 0x10)
                {
                    if (CurrentInjectionInfo->BufferBase && lpBuffer > CurrentInjectionInfo->BufferBase && 
                        lpBuffer < (LPVOID)((UINT_PTR)CurrentInjectionInfo->BufferBase + CurrentInjectionInfo->BufferSizeOfImage) && CurrentInjectionInfo->ImageDumped == TRUE)
                    {   
                        // Looks like a previously dumped PE image is being written a section at a time to the target process.
                        // We don't want to dump these writes.
                        DoOutputDebugString("WriteProcessMemory hook: injection of section of PE image which has already been dumped.\n");
                    }
                    else
                    {
                        DoOutputDebugString("WriteProcessMemory hook: Shellcode at 0x%x (size 0x%x) injected into process %d.\n", lpBuffer, *lpNumberOfBytesWritten, pid);
                    
                        // dump injected code to .bin file
                        CapeMetaData->DumpType = INJECTION_SHELLCODE;
                        CapeMetaData->TargetPid = pid;
                        if (DumpMemory((LPVOID)lpBuffer, *lpNumberOfBytesWritten))
                            DoOutputDebugString("WriteProcessMemory hook: Dumped injected code from buffer.");
                        else
                            DoOutputDebugString("WriteProcessMemory hook: Failed to dump injected code from buffer.");
                    }
                }
            }
        }
    }

	if (pid != GetCurrentProcessId()) {
		LOQ_bool("process", "ppBhs", "ProcessHandle", hProcess, "BaseAddress", lpBaseAddress,
			"Buffer", lpNumberOfBytesWritten, lpBuffer, "BufferLength", *lpNumberOfBytesWritten, "StackPivoted", is_stack_pivoted() ? "yes" : "no");

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

	if (pid != GetCurrentProcessId()) {
		LOQ_bool("process", "pxbhs", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"Buffer", NumberOfBytesWritten->LowPart, Buffer, "BufferLength", NumberOfBytesWritten->LowPart, "StackPivoted", is_stack_pivoted() ? "yes" : "no");

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

	if (NewAccessProtection == PAGE_EXECUTE_READ && BaseAddress && NumberOfBytesToProtect &&
		GetCurrentProcessId() == our_getprocessid(ProcessHandle) && is_in_dll_range((ULONG_PTR)*BaseAddress))
		restore_hooks_on_range((ULONG_PTR)*BaseAddress, (ULONG_PTR)*BaseAddress + *NumberOfBytesToProtect);
	
	ret = Old_NtProtectVirtualMemory(ProcessHandle, BaseAddress,
        NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);

	/* Don't log an uninteresting case */
	//if (OldAccessProtection && *OldAccessProtection == NewAccessProtection)
	//	return ret;

	memset(&meminfo, 0, sizeof(meminfo));
	if (NT_SUCCESS(ret)) {
		lasterror_t lasterrors;
		get_lasterrors(&lasterrors);
		VirtualQueryEx(ProcessHandle, *BaseAddress, &meminfo, sizeof(meminfo));
		set_lasterrors(&lasterrors);
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

	if (flNewProtect == PAGE_EXECUTE_READ && GetCurrentProcessId() == our_getprocessid(hProcess) &&
		is_in_dll_range((ULONG_PTR)lpAddress))
		restore_hooks_on_range((ULONG_PTR)lpAddress, (ULONG_PTR)lpAddress + dwSize);

	ret = Old_VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect,
        lpflOldProtect);

	/* Don't log an uninteresting case */
	//if (lpflOldProtect && *lpflOldProtect == flNewProtect)
	//	return ret;

	memset(&meminfo, 0, sizeof(meminfo));
	if (ret) {
		lasterror_t lasterrors;
		get_lasterrors(&lasterrors);
		VirtualQueryEx(hProcess, lpAddress, &meminfo, sizeof(meminfo));
		set_lasterrors(&lasterrors);
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

	if (GetCurrentProcessId() != our_getprocessid(ProcessHandle)) {
		LOQ_ntstatus("process", "pPPh", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"RegionSize", RegionSize, "FreeType", FreeType);
	}

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
