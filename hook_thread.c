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
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include "hook_sleep.h"
#include "unhook.h"
#include "lookup.h"
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);

static lookup_t g_ignored_threads;

extern DWORD ChildProcessId;

void ignored_threads_init(void)
{
	lookup_init(&g_ignored_threads);
}

BOOLEAN is_ignored_thread(DWORD tid)
{
	void *ret;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);
	ret = lookup_get(&g_ignored_threads, (unsigned int)tid, NULL);
	set_lasterrors(&lasterror);

	if (ret)
		return TRUE;
	return FALSE;
}

void remove_ignored_thread(DWORD tid)
{
	lasterror_t lasterror;

	get_lasterrors(&lasterror);
	lookup_del(&g_ignored_threads, tid);
	set_lasterrors(&lasterror);
}

void add_ignored_thread(DWORD tid)
{
	lasterror_t lasterror;

	get_lasterrors(&lasterror);
	pipe("INFO:Adding ignored thread %d", tid);
	lookup_add(&g_ignored_threads, tid, 0);
	set_lasterrors(&lasterror);
}


HOOKDEF(NTSTATUS, WINAPI, NtQueueApcThread,
	__in HANDLE ThreadHandle,
	__in PIO_APC_ROUTINE ApcRoutine,
	__in_opt PVOID ApcRoutineContext,
	__in_opt PIO_STATUS_BLOCK ApcStatusBlock,
	__in_opt ULONG ApcReserved
) {
	DWORD PID = pid_from_thread_handle(ThreadHandle);
	DWORD TID = tid_from_thread_handle(ThreadHandle);
	NTSTATUS ret;

	pipe("PROCESS:%d:%d,%d", is_suspended(PID, TID), PID, TID);

	ret = Old_NtQueueApcThread(ThreadHandle, ApcRoutine,
							   ApcRoutineContext, ApcStatusBlock, ApcReserved);

	LOQ_ntstatus("threading", "iip", "ProcessId", PID, "ThreadId", TID, "ThreadHandle", ThreadHandle);

	if (NT_SUCCESS(ret))
		disable_sleep_skip();
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueueApcThreadEx,
	__in HANDLE ThreadHandle,
	__in_opt HANDLE UserApcReserveHandle,
	__in PIO_APC_ROUTINE ApcRoutine,
	__in_opt PVOID ApcRoutineContext,
	__in_opt PIO_STATUS_BLOCK ApcStatusBlock,
	__in_opt PVOID ApcReserved
) {
	DWORD PID = pid_from_thread_handle(ThreadHandle);
	DWORD TID = tid_from_thread_handle(ThreadHandle);
	NTSTATUS ret;

	pipe("PROCESS:%d:%d,%d", is_suspended(PID, TID), PID, TID);

	ret = Old_NtQueueApcThreadEx(ThreadHandle, UserApcReserveHandle, ApcRoutine,
								 ApcRoutineContext, ApcStatusBlock, ApcReserved);

	LOQ_ntstatus("threading", "iip", "ProcessId", PID, "ThreadId", TID, "ThreadHandle", ThreadHandle);

	if (NT_SUCCESS(ret))
		disable_sleep_skip();
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateThread,
	__out     PHANDLE ThreadHandle,
	__in      ACCESS_MASK DesiredAccess,
	__in_opt  POBJECT_ATTRIBUTES ObjectAttributes,
	__in      HANDLE ProcessHandle,
	__out     PCLIENT_ID ClientId,
	__in      PCONTEXT ThreadContext,
	__in      PINITIAL_TEB InitialTeb,
	__in      BOOLEAN CreateSuspended
	) {
	DWORD pid = pid_from_process_handle(ProcessHandle);

	NTSTATUS ret = Old_NtCreateThread(ThreadHandle, DesiredAccess,
		ObjectAttributes, ProcessHandle, ClientId, ThreadContext,
		InitialTeb, TRUE);

	if (NT_SUCCESS(ret)) {
		//if (called_by_hook() && pid == GetCurrentProcessId())
		//	add_ignored_thread((DWORD)ClientId->UniqueThread);
		pipe("PROCESS:%d:%d,%d", is_suspended(pid, (DWORD)(ULONG_PTR)ClientId->UniqueThread), pid, (DWORD)(ULONG_PTR)ClientId->UniqueThread);
		
            if (!called_by_hook() && DEBUGGER_ENABLED)
            {
                DoOutputDebugString("NtCreateThread: calling InitNewThreadBreakpoints");
                InitNewThreadBreakpoints((DWORD)(ULONG_PTR)ClientId->UniqueThread);
            }
        
        if (CreateSuspended == FALSE) {
			lasterror_t lasterror;
			get_lasterrors(&lasterror);
			ResumeThread(*ThreadHandle);
			set_lasterrors(&lasterror);
		}
	}

	LOQ_ntstatus("threading", "PpOi", "ThreadHandle", ThreadHandle, "ProcessHandle", ProcessHandle,
        "ObjectAttributes", ObjectAttributes, "CreateSuspended", CreateSuspended);

	if (NT_SUCCESS(ret))
        disable_sleep_skip();
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateThreadEx,
    OUT     PHANDLE hThread,
    IN      ACCESS_MASK DesiredAccess,
    IN      PVOID ObjectAttributes,
    IN      HANDLE ProcessHandle,
    IN      LPTHREAD_START_ROUTINE lpStartAddress,
    IN      PVOID lpParameter,
    IN      DWORD dwCreationFlags,
    IN      LONG StackZeroBits,
    IN      LONG SizeOfStackCommit,
    IN      LONG SizeOfStackReserve,
    OUT     PVOID lpBytesBuffer
) {
	DWORD pid = pid_from_process_handle(ProcessHandle);
	
	NTSTATUS ret = Old_NtCreateThreadEx(hThread, DesiredAccess,
        ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter,
        dwCreationFlags | THREAD_CREATE_FLAGS_CREATE_SUSPENDED, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve,
        lpBytesBuffer);

	if (NT_SUCCESS(ret)) {
		DWORD tid = tid_from_thread_handle(*hThread);
		//if (called_by_hook() && pid == GetCurrentProcessId())
		//	add_ignored_thread(tid);

        if (!called_by_hook() && DEBUGGER_ENABLED)
        {
            DoOutputDebugString("NtCreateThreadEx: calling InitNewThreadBreakpoints");
            InitNewThreadBreakpoints(tid);
        }
        
        pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);
		if (!(dwCreationFlags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED)) {
			lasterror_t lasterror;
			get_lasterrors(&lasterror);
			ResumeThread(*hThread);
			set_lasterrors(&lasterror);
		}
            
        LOQ_ntstatus("threading", "iPpph", "ThreadId", tid, "ThreadHandle", hThread, "ProcessHandle", ProcessHandle,
            "StartAddress", lpStartAddress, "CreationFlags", dwCreationFlags);
	}
	else
        LOQ_ntstatus("threading", "Ppph", "ThreadHandle", hThread, "ProcessHandle", ProcessHandle,
            "StartAddress", lpStartAddress, "CreationFlags", dwCreationFlags);

	if (NT_SUCCESS(ret))
		disable_sleep_skip();
	
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenThread,
    __out  PHANDLE ThreadHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes,
    __in   PCLIENT_ID ClientId
) {
    NTSTATUS ret = Old_NtOpenThread(ThreadHandle, DesiredAccess,
        ObjectAttributes, ClientId);
	DWORD PID = 0;
	DWORD TID = 0;

	if (NT_SUCCESS(ret) && ThreadHandle) {
		PID = pid_from_thread_handle(*ThreadHandle);
		TID = tid_from_thread_handle(*ThreadHandle);
	}

	if (ClientId) {
		LOQ_ntstatus("threading", "Phii", "ThreadHandle", ThreadHandle, "DesiredAccess", DesiredAccess,
			"ProcessId", PID, "ThreadId", TID);
	} else {
		LOQ_ntstatus("threading", "PhO", "ThreadHandle", ThreadHandle, "DesiredAccess", DesiredAccess,
			"ObjectAttributes", ObjectAttributes);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtGetContextThread,
    __in     HANDLE ThreadHandle,
    __inout  LPCONTEXT Context
) {
	DWORD pid = pid_from_thread_handle(ThreadHandle);

    NTSTATUS ret = Old_NtGetContextThread(ThreadHandle, Context);
	
    if (called_by_hook())
        return ret;
        
    if (Context->ContextFlags & CONTEXT_CONTROL)
    {
        if 
        (
            DEBUGGER_ENABLED && 
            pid == ChildProcessId && 
            OEP && 
#ifdef _WIN64

            DebuggerEP == Context->Rcx
#else

            DebuggerEP == Context->Eax
#endif
        )
        {
#ifdef _WIN64
            Context->Rcx = (DWORD_PTR)OEP;
#else
            Context->Eax = (DWORD)OEP;
#endif
        }

#ifdef _WIN64
        LOQ_ntstatus("threading", "pp", "ThreadHandle", ThreadHandle, "InstructionPointer", Context->Rcx);
#else
        LOQ_ntstatus("threading", "pp", "ThreadHandle", ThreadHandle, "InstructionPointer", Context->Eax);
#endif
    }
	else
		LOQ_ntstatus("threading", "p", "ThreadHandle", ThreadHandle);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetContextThread,
    __in  HANDLE ThreadHandle,
    __in  CONTEXT *Context
) {
	NTSTATUS ret;
	DWORD pid = pid_from_thread_handle(ThreadHandle);
	DWORD tid = tid_from_thread_handle(ThreadHandle);
	pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);

	if (DEBUGGER_ENABLED && pid == ChildProcessId && Context->ContextFlags & CONTEXT_CONTROL)
    {
        if (!DebuggerEP)
            DoOutputDebugString("NtSetContextThread hook: Error - DebuggerEP not set.\n");
        else
        {
#ifdef _WIN64
			SendDebuggerMessage((DWORD_PTR)Context->Rcx);
            DoOutputDebugString("NtSetContextThread hook: Sent new child EP to Debugger - 0x%x\n", Context->Rcx);
#else
			SendDebuggerMessage((DWORD_PTR)Context->Eax);
            DoOutputDebugString("NtSetContextThread hook: Sent new child EP to Debugger - 0x%x\n", Context->Eax);
#endif
            Context->ContextFlags = Context->ContextFlags |~ CONTEXT_CONTROL;
            
            ret = Old_NtSetContextThread(ThreadHandle, Context);

            Context->ContextFlags = Context->ContextFlags & CONTEXT_CONTROL;
        }
    }
    else
        ret = Old_NtSetContextThread(ThreadHandle, Context);
        
	if (Context->ContextFlags & CONTEXT_CONTROL)
#ifdef _WIN64
		LOQ_ntstatus("threading", "pp", "ThreadHandle", ThreadHandle, "InstructionPointer", Context->Rcx);
#else
		LOQ_ntstatus("threading", "pp", "ThreadHandle", ThreadHandle, "InstructionPointer", Context->Eax);
#endif
	else
		LOQ_ntstatus("threading", "p", "ThreadHandle", ThreadHandle);

    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSuspendThread,
    __in        HANDLE ThreadHandle,
    __out_opt   ULONG *PreviousSuspendCount
) {
	DWORD pid = pid_from_thread_handle(ThreadHandle);
	DWORD tid = tid_from_thread_handle(ThreadHandle);
	NTSTATUS ret;
	ENSURE_ULONG(PreviousSuspendCount);

	if (pid == GetCurrentProcessId() && tid && (tid == g_unhook_detect_thread_id || tid == g_unhook_watcher_thread_id ||
		tid == g_watchdog_thread_id || tid == g_terminate_event_thread_id || tid == g_log_thread_id ||
		tid == g_logwatcher_thread_id || tid == g_procname_watcher_thread_id)) {
		ret = 0;
		*PreviousSuspendCount = 0;
		LOQ_ntstatus("threading", "pLs", "ThreadHandle", ThreadHandle,
			"SuspendCount", PreviousSuspendCount, "Alert", "Attempted to suspend cuckoomon thread");
	}
	else {
		pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);

		ret = Old_NtSuspendThread(ThreadHandle, PreviousSuspendCount);
		LOQ_ntstatus("threadingb", "pL", "ThreadHandle", ThreadHandle,
			"SuspendCount", PreviousSuspendCount);
	}
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtResumeThread,
    __in        HANDLE ThreadHandle,
    __out_opt   ULONG *SuspendCount
) {
    CONTEXT Context;
    DWORD_PTR ChildNewEP;
	DWORD pid = pid_from_thread_handle(ThreadHandle);
	DWORD tid = tid_from_thread_handle(ThreadHandle);
	NTSTATUS ret;
	ENSURE_ULONG(SuspendCount);
	pipe("RESUME:%d,%d", pid, tid);
    
    if (DEBUGGER_ENABLED && pid == ChildProcessId && tid == ChildThreadId)
    {
        Context.ContextFlags = CONTEXT_ALL;
        
        ret = Old_NtGetContextThread(ThreadHandle, &Context);

        if (NT_SUCCESS(ret))
        {
#ifdef _WIN64
            if (Context.Rcx != DebuggerEP)
            {
                ChildNewEP = Context.Rcx;
                Context.Rcx = DebuggerEP;
#else
            if (Context.Eax != DebuggerEP)
            {
                ChildNewEP = Context.Eax;
                Context.Eax = DebuggerEP;
#endif
                ret = Old_NtSetContextThread(ThreadHandle, &Context);
                
                if (NT_SUCCESS(ret))
                {
                    SendDebuggerMessage((DWORD_PTR)ChildNewEP);
                    DoOutputDebugString("NtResumeThread: Reset Debugger entry (0x%x) in child process, updated EP to 0x%x.\n", DebuggerEP, ChildNewEP);
                }
                else
                    DoOutputDebugString("NtResumeThread: Error - failed to ensure Debugger entry in child process.\n");
            }
        }
        else
        {
            DoOutputDebugString("NtResumeThread: NtGetContextThread failed.\n");
        }        
    }

    ret = Old_NtResumeThread(ThreadHandle, SuspendCount);
    LOQ_ntstatus("threading", "ipI", "ThreadId", tid, "ThreadHandle", ThreadHandle, "SuspendCount", SuspendCount);
    return ret;
}

extern DWORD tmphookinfo_threadid;
extern CRITICAL_SECTION g_tmp_hookinfo_lock;

HOOKDEF(NTSTATUS, WINAPI, NtTerminateThread,
    __in  HANDLE ThreadHandle,
    __in  NTSTATUS ExitStatus
) {
    // Thread will terminate. Default logging will not work. Be aware: return value not valid
	DWORD pid = pid_from_thread_handle(ThreadHandle);
	DWORD tid = tid_from_thread_handle(ThreadHandle);
	NTSTATUS ret = 0;

	if (tmphookinfo_threadid && tid == tmphookinfo_threadid) {
		tmphookinfo_threadid = 0;
		LeaveCriticalSection(&g_tmp_hookinfo_lock);
	}

	//remove_ignored_thread(tid);

	if (pid == GetCurrentProcessId() && tid && (tid == g_unhook_detect_thread_id || tid == g_unhook_watcher_thread_id ||
		tid == g_watchdog_thread_id || tid == g_terminate_event_thread_id || tid == g_log_thread_id ||
		tid == g_logwatcher_thread_id || tid == g_procname_watcher_thread_id)) {
		ret = 0;
		LOQ_ntstatus("threading", "phs", "ThreadHandle", ThreadHandle, "ExitStatus", ExitStatus, "Alert", "Attempted to kill cuckoomon thread");
		return ret;
	}

	LOQ_ntstatus("threading", "iph", "ThreadId", tid, "ThreadHandle", ThreadHandle, "ExitStatus", ExitStatus);
    ret = Old_NtTerminateThread(ThreadHandle, ExitStatus);

	disable_tail_call_optimization();

	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateThread,
    __in   LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in   SIZE_T dwStackSize,
    __in   LPTHREAD_START_ROUTINE lpStartAddress,
    __in   LPVOID lpParameter,
    __in   DWORD dwCreationFlags,
    __out_opt  LPDWORD lpThreadId
) {
	HANDLE ret;
	ENSURE_DWORD(lpThreadId);

	ret = Old_CreateThread(lpThreadAttributes, dwStackSize,
        lpStartAddress, lpParameter, dwCreationFlags | CREATE_SUSPENDED, lpThreadId);
    
    if (!called_by_hook() && DEBUGGER_ENABLED)
    {
        DoOutputDebugString("CreateThread: calling InitNewThreadBreakpoints");
        InitNewThreadBreakpoints(*lpThreadId);
    }

    if (!(dwCreationFlags && CREATE_SUSPENDED)) {
        lasterror_t lasterror;
        get_lasterrors(&lasterror);
        ResumeThread(ret);
        set_lasterrors(&lasterror);
    }
        
    LOQ_nonnull("threading", "pphI", "StartRoutine", lpStartAddress, "Parameter", lpParameter,
        "CreationFlags", dwCreationFlags, "ThreadId", lpThreadId);
    if (ret != NULL)
        disable_sleep_skip();
    return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateRemoteThread,
    __in   HANDLE hProcess,
    __in   LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in   SIZE_T dwStackSize,
    __in   LPTHREAD_START_ROUTINE lpStartAddress,
    __in   LPVOID lpParameter,
    __in   DWORD dwCreationFlags,
    __out_opt  LPDWORD lpThreadId
) {
	DWORD pid;
	HANDLE ret;
	ENSURE_DWORD(lpThreadId);

	pid = pid_from_process_handle(hProcess);

    if (pid == ChildProcessId)
    {
        DoOutputDebugString("CreateRemoteThread: RemoteThread created in child process, sending address to debugger: 0x%x", lpStartAddress);
        SendDebuggerMessage((DWORD_PTR)lpStartAddress);
        ret = Old_CreateRemoteThread(hProcess, lpThreadAttributes,
            dwStackSize, (LPTHREAD_START_ROUTINE)DebuggerEP, lpParameter, dwCreationFlags | CREATE_SUSPENDED,
            lpThreadId);
    }
    else ret = Old_CreateRemoteThread(hProcess, lpThreadAttributes,
        dwStackSize, lpStartAddress, lpParameter, dwCreationFlags | CREATE_SUSPENDED,
        lpThreadId);

	if (ret != NULL) {    
        if (pid == GetCurrentProcessId()) {
            if (!called_by_hook() && DEBUGGER_ENABLED)
            {
                DoOutputDebugString("CreateRemoteThread: calling InitNewThreadBreakpoints");
                InitNewThreadBreakpoints(*lpThreadId);
            }
        }
        else
            pipe("PROCESS:%d:%d,%d", is_suspended(pid, *lpThreadId), pid, *lpThreadId);
        
		if (!(dwCreationFlags & CREATE_SUSPENDED)) {
			lasterror_t lasterror;
			get_lasterrors(&lasterror);
			ResumeThread(ret);
			set_lasterrors(&lasterror);
		}
	}

	LOQ_nonnull("threading", "ppphI", "ProcessHandle", hProcess, "StartRoutine", lpStartAddress,
        "Parameter", lpParameter, "CreationFlags", dwCreationFlags,
        "ThreadId", lpThreadId);

	if (ret != NULL)
		disable_sleep_skip();
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, RtlCreateUserThread,
    IN HANDLE ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG StackZeroBits,
    IN OUT PULONG StackReserved,
    IN OUT PULONG StackCommit,
    IN PVOID StartAddress,
    IN PVOID StartParameter OPTIONAL,
    OUT PHANDLE ThreadHandle,
    OUT PCLIENT_ID ClientId
) {
	DWORD pid;
	NTSTATUS ret;
	ENSURE_CLIENT_ID(ClientId);

	pid = pid_from_process_handle(ProcessHandle);
	
    if (pid == ChildProcessId)
    {
        DoOutputDebugString("RtlCreateUserThread: RemoteThread created in child process, sending address to debugger: 0x%x", StartAddress);
        SendDebuggerMessage((DWORD_PTR)StartAddress);
        ret = Old_RtlCreateUserThread(ProcessHandle, SecurityDescriptor,
            TRUE, StackZeroBits, StackReserved, StackCommit,
            (LPTHREAD_START_ROUTINE)DebuggerEP, StartParameter, ThreadHandle, ClientId);
    }
    else ret = Old_RtlCreateUserThread(ProcessHandle, SecurityDescriptor,
            TRUE, StackZeroBits, StackReserved, StackCommit,
            StartAddress, StartParameter, ThreadHandle, ClientId);
            
    LOQ_ntstatus("threading", "pippPi", "ProcessHandle", ProcessHandle,
        "CreateSuspended", CreateSuspended, "StartAddress", StartAddress,
        "StartParameter", StartParameter, "ThreadHandle", ThreadHandle,
        "ThreadIdentifier", ClientId->UniqueThread);

	if (NT_SUCCESS(ret)) {    
        if (pid == GetCurrentProcessId()) {
            if (!called_by_hook() && DEBUGGER_ENABLED)
            {
                DoOutputDebugString("RtlCreateUserThread: calling InitNewThreadBreakpoints");
                InitNewThreadBreakpoints((DWORD)(ULONG_PTR)ClientId->UniqueThread);
            }
        }
        else
            pipe("PROCESS:%d:%d,%d", is_suspended(pid, (DWORD)(ULONG_PTR)ClientId->UniqueThread), pid, (DWORD)(ULONG_PTR)ClientId->UniqueThread);
        
		if (CreateSuspended == FALSE) {
			lasterror_t lasterror;
			get_lasterrors(&lasterror);
			ResumeThread(ThreadHandle);
			set_lasterrors(&lasterror);
		}
        
        disable_sleep_skip();
	}

	return ret;
}
