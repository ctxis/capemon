/*
CAPE - Config And Payload Extraction
Copyright(C) 2015 - 2018 Context Information Security. (kevin.oreilly@contextis.com)

This program is free software : you can redistribute it and / or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.
*/
#include "Loader.h"
#include <tlhelp32.h>
#include <strsafe.h>

SYSTEM_INFO SystemInfo;

void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...)
{
    char DebugOutput[MAX_PATH];
    va_list args;
    va_start(args, lpOutputString);

    memset(DebugOutput, 0, MAX_PATH*sizeof(char));
    _vsnprintf_s(DebugOutput, MAX_PATH, MAX_PATH, lpOutputString, args);
    OutputDebugString(DebugOutput);
    
    va_end(args);
	
    return;
}

void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...)
{
    char DebugOutput[MAX_PATH], ErrorOutput[MAX_PATH];
    va_list args;
    LPVOID lpMsgBuf;
    DWORD ErrorCode; 

    ErrorCode = GetLastError(); 
    va_start(args, lpOutputString);

    FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        ErrorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0, 
		NULL);
    
    memset(DebugOutput, 0, MAX_PATH*sizeof(char));
    _vsnprintf_s(DebugOutput, MAX_PATH, MAX_PATH, lpOutputString, args);
    memset(ErrorOutput, 0, MAX_PATH*sizeof(char));
    _snprintf_s(ErrorOutput, MAX_PATH, MAX_PATH, "Error %d (0x%x) - %s: %s", ErrorCode, ErrorCode, DebugOutput, (char*)lpMsgBuf);
    OutputDebugString(ErrorOutput);
    
    va_end(args);

	return;
}

PVOID GetProcessImageBase(HANDLE ProcessHandle)
{
    _NtQueryInformationProcess pNtQueryInformationProcess;
	PROCESS_BASIC_INFORMATION ProcessBasicInformation;
	ULONG ulSize;
	PEB Peb;
    SIZE_T dwBytesRead;
	PVOID pPEB = 0;

	if (ProcessHandle == GetCurrentProcess())
    {
        return GetModuleHandle(NULL);
	}

    pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");
	
    memset(&ProcessBasicInformation, 0, sizeof(ProcessBasicInformation));
	
    if (pNtQueryInformationProcess(ProcessHandle, 0, &ProcessBasicInformation, sizeof(ProcessBasicInformation), &ulSize) >= 0 && ulSize == sizeof(ProcessBasicInformation))
    {
        pPEB = ProcessBasicInformation.PebBaseAddress;
        
        if (ReadProcessMemory(ProcessHandle, pPEB, &Peb, sizeof(Peb), &dwBytesRead))
            return Peb.ImageBaseAddress;
    }
 
    return NULL;
}

DWORD GetProcessInitialThreadId(HANDLE ProcessHandle)
{
    DWORD ThreadId;

    __try 
    {
        PTEB Teb = (PTEB)NtCurrentTeb();

        if (!ReadProcessMemory(ProcessHandle, &Teb->ClientId.UniqueThread, &ThreadId, sizeof(DWORD), NULL))
        {
            DoOutputErrorString("GetProcessInitialThreadId: Failed to read from process");
            return 0;
        }
    
        if (ThreadId)
            return ThreadId;
        
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) 
    {
        return 0;
    }
}

static int GrantDebugPrivileges(void)
{
    HANDLE Token = NULL;
    TOKEN_PRIVILEGES TokenPrivileges;
    LUID PrivilegeValue;
    int RetVal;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token))
        return 0;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &PrivilegeValue)) 
    {
        CloseHandle(Token);
        return 0;
    }
    
    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Luid = PrivilegeValue;
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    RetVal = AdjustTokenPrivileges(Token, FALSE, &TokenPrivileges, sizeof(TokenPrivileges), NULL, NULL);
    CloseHandle(Token);

    return RetVal;
}

__declspec(noinline) DWORD WINAPI LoadLibraryThreadFunc(LoadLibraryThread *Pointers)
{
    HMODULE ModuleHandle; 
    
    ModuleHandle = (HMODULE)Pointers->LoadLibrary(Pointers->DllPath);

    if (ModuleHandle == NULL)
        return (DWORD)Pointers->GetLastError();
    
    return 0;
}

static int InjectDllViaThread(HANDLE ProcessHandle, HANDLE ThreadHandle, const char *DllPath, BOOLEAN ForceLoad)
{
    SIZE_T DllPathLength;
    LoadLibraryThread Pointers;
    void *PointersAddress;
    void *RemoteFuncAddress;    
    OSVERSIONINFO OSVersion;
    SIZE_T BytesWritten;
    HANDLE RemoteThreadHandle;
    DWORD ExitCode;
    _RtlCreateUserThread pRtlCreateUserThread;    
    int RetVal = 0;
    
    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);
    
    if (!SystemInfo.dwPageSize)
    {
        DoOutputErrorString("InjectDllViaThread: Failed to obtain system page size");
        return 0;
    }
    
    DllPathLength = strlen(DllPath) + 1;
    
    if (DllPathLength == 0)
    {
        DoOutputDebugString("InjectDllViaThread: Dll argument bad.\n");
        return 0;
    }

    memset(&Pointers, 0, sizeof(Pointers));

    Pointers.LoadLibrary = GetProcAddress(LoadLibrary("kernel32"), "LoadLibraryA");
    Pointers.GetLastError = GetProcAddress(LoadLibrary("kernel32"),  "GetLastError");

    if (!Pointers.LoadLibrary || !Pointers.GetLastError)
    {
        DoOutputDebugString("InjectDllViaThread: Failed to get function pointers.\n");
        return 0;
    }

    Pointers.DllPath = (PCHAR)VirtualAllocEx(ProcessHandle, NULL, SystemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (Pointers.DllPath == NULL)
    {
        DoOutputErrorString("InjectDllViaThread: Failed to allocate buffer in target");
        return ERROR_ALLOCATE;
    }
    
    if (WriteProcessMemory(ProcessHandle, Pointers.DllPath, DllPath, DllPathLength, &BytesWritten) == FALSE || BytesWritten != DllPathLength) 
    {
        DoOutputErrorString("InjectDllViaThread: Failed to write to DllPath in target");
        return ERROR_WRITEMEMORY;
    }
    
    PointersAddress = (PBYTE)Pointers.DllPath + BytesWritten;
    
    if (WriteProcessMemory(ProcessHandle, PointersAddress, &Pointers, sizeof(Pointers), &BytesWritten) == FALSE || BytesWritten != sizeof(Pointers)) 
    {
        DoOutputErrorString("InjectDllViaThread: Failed to write to PointersAddress in target");
        return ERROR_WRITEMEMORY;
    }
    
    RemoteFuncAddress = (PBYTE)PointersAddress + BytesWritten;

    if (WriteProcessMemory(ProcessHandle, RemoteFuncAddress, (PBYTE)(&LoadLibraryThreadFunc), 0x100, &BytesWritten) == FALSE || BytesWritten != 0x100) 
    {
        DoOutputErrorString("InjectDllViaThread: Failed to write to RemoteFuncAddress in target");
        return ERROR_WRITEMEMORY;
    }
    
    // If we aren't going to force immediate loading, we queue an APC thread
    if (!ForceLoad && ThreadHandle)
    {
        if (QueueUserAPC((PAPCFUNC)RemoteFuncAddress, ThreadHandle, (ULONG_PTR)PointersAddress) == 0) 
        {
            DoOutputErrorString("InjectDllViaThread: QueueUserAPC failed");
            return 0;
        }
        
        DoOutputDebugString("InjectDllViaThread: APC injection queued.\n");
        
        return 1;
    }

    OSVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    
    if (!GetVersionEx(&OSVersion))
    {
        DoOutputErrorString("InjectDllViaThread: Failed to get OS version");
        return 0;
    }
    
    if (OSVersion.dwMajorVersion < 6)
    {
        RemoteThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 0, RemoteFuncAddress, PointersAddress, 0, NULL);
        
        if (!RemoteThreadHandle)
        {
            DoOutputErrorString("InjectDllViaThread: CreateRemoteThread failed");
            return ERROR_CREATEREMOTETHREAD;
        }
        else
        {
            WaitForSingleObject(RemoteThreadHandle, INFINITE);
            GetExitCodeThread(RemoteThreadHandle, &ExitCode);
            CloseHandle(RemoteThreadHandle);
            VirtualFreeEx(ProcessHandle, Pointers.DllPath, SystemInfo.dwPageSize, MEM_RELEASE);
            
            if (ExitCode)
            {
                SetLastError(ExitCode);
                DoOutputErrorString("InjectDllViaThread: CreateRemoteThread injection failed");
                return 0;
            }

            DoOutputDebugString("InjectDllViaThread: Successfully injected Dll into process via CreateRemoteThread.\n");
            
            return 1;
        }
    }
    else
    {
        pRtlCreateUserThread = (_RtlCreateUserThread)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCreateUserThread");
        
        RetVal = pRtlCreateUserThread(ProcessHandle, NULL, 0, 0, 0, 0, (PTHREAD_START_ROUTINE)RemoteFuncAddress, PointersAddress, &RemoteThreadHandle, NULL);
        
        if (!NT_SUCCESS(RetVal))
        {
            RemoteThreadHandle = NULL;
            DoOutputErrorString("InjectDllViaThread: RtlCreateUserThread failed");
            return ERROR_RTLCREATEUSERTHREAD;
        }
        else if(RemoteThreadHandle)
        {
            WaitForSingleObject(RemoteThreadHandle, INFINITE);
            GetExitCodeThread(RemoteThreadHandle, &ExitCode);
            CloseHandle(RemoteThreadHandle);
            VirtualFreeEx(ProcessHandle, Pointers.DllPath, SystemInfo.dwPageSize, MEM_RELEASE);
            
            if (ExitCode)
            {
                SetLastError(ExitCode);
                DoOutputErrorString("InjectDllViaThread: RtlCreateUserThread injection failed");
                return ERROR_RTLCREATEUSERTHREAD;
            }
        }            
        
        DoOutputDebugString("InjectDllViaThread: Successfully injected Dll into process via RtlCreateUserThread.\n");
        
        return 1;
    }
}

static int InjectDllViaIAT(HANDLE ProcessHandle, HANDLE ThreadHandle, const char *DllPath)
{
    SIZE_T DllPathLength;
    IMAGE_DOS_HEADER DosHeader;
    IMAGE_NT_HEADERS NtHeader;
    CONTEXT Context;
    MEMORY_BASIC_INFORMATION MemoryInfo;
    DWORD NewImportDirectorySize, OriginalNumberOfDescriptors, NewNumberOfDescriptors, NewSizeOfImportDescriptors, SizeOfTables, NewImportsRVA, dwProtect, SizeOfHeaders;
    PBYTE BaseAddress, FreeAddress, EndOfImage, TargetImportTable, AllocationAddress, NewImportDirectory;
    IMAGE_SECTION_HEADER ImportsSection;
    PIMAGE_IMPORT_DESCRIPTOR pImageDescriptor;
    PIMAGE_THUNK_DATAXX pOriginalFirstThunk, pFirstThunk;
    unsigned int i, OrdinalValue;
    SIZE_T BytesRead;
    int RetVal = 0;
    
    NewImportDirectorySize = 0;
    NewImportDirectory = NULL;

    memset(&DosHeader, 0, sizeof(DosHeader));
    memset(&NtHeader, 0, sizeof(NtHeader));
    memset(&MemoryInfo, 0, sizeof(MemoryInfo));
    
    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);
    
    if (!SystemInfo.dwPageSize)
    {
        DoOutputErrorString("InjectDllViaIAT: Failed to obtain system page size");
        return 0;
    }

    DllPathLength = strlen(DllPath) + 1;
    
    if (DllPathLength == 0)
    {
        DoOutputDebugString("InjectDllViaIAT: Dll argument bad.\n");
        return ERROR_INVALID_PARAM;
    }

    BaseAddress = GetProcessImageBase(ProcessHandle);
    
    if (BaseAddress == NULL)
    {
        DoOutputDebugString("InjectDllViaIAT: GetProcessImageBase failed.\n");
        goto out;
    }
    
    DoOutputDebugString("Process image base: 0x%p\n", BaseAddress);

    if (!VirtualQueryEx(ProcessHandle, (PVOID)BaseAddress, &MemoryInfo, sizeof(MemoryInfo))) 
    {
        DoOutputDebugString("InjectDllViaIAT: Failed to query target process image base.\n");
        goto out;
    }
    
    if (!ReadProcessMemory(ProcessHandle, BaseAddress, &DosHeader, sizeof(DosHeader), NULL)) 
    {
        DoOutputErrorString("InjectDllViaIAT: Failed to read DOS header from 0x%p - 0x%p", BaseAddress, BaseAddress + sizeof(DosHeader));
        RetVal = ERROR_READMEMORY;
        goto out;
    }

    if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE || (DWORD)DosHeader.e_lfanew < sizeof(DosHeader))
    {
        DoOutputDebugString("InjectDllViaIAT: Executable DOS header invalid.\n");
        goto out;
    }

    if (!ReadProcessMemory(ProcessHandle, BaseAddress + DosHeader.e_lfanew, &NtHeader, sizeof(NtHeader), NULL)) 
    {
        DoOutputErrorString("InjectDllViaIAT: Failed to read NT headers from 0x%p - 0x%p", BaseAddress + DosHeader.e_lfanew, BaseAddress + DosHeader.e_lfanew + sizeof(NtHeader));
        RetVal = ERROR_READMEMORY;
        goto out;
    }

#ifdef _WIN64
    if (NtHeader.Signature != IMAGE_NT_SIGNATURE || NtHeader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || NtHeader.FileHeader.Machine == 0)
#else
    if (NtHeader.Signature != IMAGE_NT_SIGNATURE || NtHeader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC || NtHeader.FileHeader.Machine == 0)
#endif
    {
        DoOutputDebugString("InjectDllViaIAT: Executable image invalid.\n");
        goto out;
    }

    Context.ContextFlags = CONTEXT_ALL;
    
    if (!GetThreadContext(ThreadHandle, &Context))
    {
        DoOutputDebugString("InjectDllViaIAT: GetThreadContext failed");
        goto out;
    }
    
#ifdef _WIN64
    if (Context.Rcx != (DWORD_PTR)(BaseAddress + NtHeader.OptionalHeader.AddressOfEntryPoint))
#else
    if (Context.Eax != (DWORD_PTR)(BaseAddress + NtHeader.OptionalHeader.AddressOfEntryPoint))
#endif
    {
        DoOutputDebugString("InjectDllViaIAT: Not a new process, bailing.\n");
        goto out;
    }
    
    DoOutputDebugString("InjectDllViaIAT: IAT patching with dll name %s.\n", DllPath);

    SizeOfHeaders = DosHeader.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + NtHeader.FileHeader.SizeOfOptionalHeader;

    OriginalNumberOfDescriptors = NtHeader.IMPORT_DIRECTORY.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    
    NewNumberOfDescriptors = OriginalNumberOfDescriptors + 1;
    
    NewSizeOfImportDescriptors = NewNumberOfDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (NewSizeOfImportDescriptors % sizeof(DWORD_PTR))
        NewSizeOfImportDescriptors += sizeof(DWORD_PTR);  
        
    // Two for OriginalFirstThunk, NULL, then two for FirstThunk, NULL.
    SizeOfTables = NewSizeOfImportDescriptors + (4 * sizeof(IMAGE_THUNK_DATAXX)); 
    
    NewImportDirectorySize = (DWORD)(SizeOfTables + DllPathLength + sizeof(DWORD) - (DllPathLength % sizeof(DWORD)));
    
    // Allocate the memory for our new import directory
    NewImportDirectory = (PBYTE)calloc(NewImportDirectorySize, 1);
    
    if (NewImportDirectory == NULL) 
    {
        DoOutputDebugString("InjectDllViaIAT: Failed to allocate memory for new import directory.\n");
        RetVal = ERROR_ALLOCATE;
        goto out;
    }

    // Check which section (if any) contains the import table.
    memset(&ImportsSection, 0, sizeof(ImportsSection));
    
    for (i = 0; i < NtHeader.FileHeader.NumberOfSections; i++) 
    {
        IMAGE_SECTION_HEADER SectionHeader;
        memset(&SectionHeader, 0, sizeof(SectionHeader));

        if (!ReadProcessMemory(ProcessHandle, (BYTE*)BaseAddress + SizeOfHeaders + sizeof(SectionHeader) * i, &SectionHeader, sizeof(SectionHeader), &BytesRead) || BytesRead < sizeof(SectionHeader)) 
        {
            DoOutputErrorString("InjectDllViaIAT: Failed to read section header from 0x%p - 0x%p", (BYTE*)BaseAddress + SizeOfHeaders + sizeof(SectionHeader) * i, (BYTE*)BaseAddress + SizeOfHeaders + sizeof(SectionHeader) * (i + 1));
            RetVal = ERROR_READMEMORY;
            goto out;
        }

        if (NtHeader.IMPORT_DIRECTORY.VirtualAddress >= SectionHeader.VirtualAddress &&
            NtHeader.IMPORT_DIRECTORY.VirtualAddress < SectionHeader.VirtualAddress + SectionHeader.SizeOfRawData)
            ImportsSection = SectionHeader;
    }

    // If none, it looks like this image has already been patched, 
    // so we bail.
    if (ImportsSection.VirtualAddress == 0)
    {
        DoOutputDebugString("InjectDllViaIAT: This image appears to have already been patched - aborting.\n");
        goto out;
    }
    
    // Scan address space from EXE image base for a free region to contain our new import directory
    EndOfImage = BaseAddress + NtHeader.OptionalHeader.BaseOfCode + NtHeader.OptionalHeader.SizeOfCode + NtHeader.OptionalHeader.SizeOfInitializedData + NtHeader.OptionalHeader.SizeOfUninitializedData;
    
    TargetImportTable = NULL;
    
    for (FreeAddress = EndOfImage;; FreeAddress = (PBYTE)MemoryInfo.BaseAddress + MemoryInfo.RegionSize) 
    {
        memset(&MemoryInfo, 0, sizeof(MemoryInfo));
        
        if (VirtualQueryEx(ProcessHandle, (PVOID)FreeAddress, &MemoryInfo, sizeof(MemoryInfo)) == 0) 
        {
            if (GetLastError() == ERROR_INVALID_PARAMETER)
                break;

            DoOutputErrorString("InjectDllViaIAT: Failed to query target process memory at address 0x%p", FreeAddress);
            break;
        }
        
        // This indicates the end of user-mode address space
        if ((MemoryInfo.RegionSize & 0xFFF) == 0xFFF)
            break;

        if (MemoryInfo.State != MEM_FREE)
            continue;

        DoOutputDebugString("InjectDllViaIAT: Found a free region from 0x%p - 0x%p\n", MemoryInfo.BaseAddress, (PBYTE)MemoryInfo.BaseAddress + MemoryInfo.RegionSize);

        for (AllocationAddress = (PBYTE)(((DWORD_PTR)MemoryInfo.BaseAddress + 0xFFFF) & ~(DWORD_PTR)0xFFFF); AllocationAddress < (PBYTE)MemoryInfo.BaseAddress + MemoryInfo.RegionSize; AllocationAddress += SystemInfo.dwPageSize) 
        {
            TargetImportTable = (PBYTE)VirtualAllocEx(ProcessHandle, AllocationAddress, NewImportDirectorySize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            
            if (TargetImportTable == NULL) 
            {
                DoOutputErrorString("InjectDllViaIAT: Failed to allocate new memory region at 0x%p.\n", AllocationAddress);
                continue;
            }
            
#ifdef _WIN64
            if ((SIZE_T)(TargetImportTable - EndOfImage) > 0xFFFFFFFF) 
            {
                DoOutputDebugString("InjectDllViaIAT: Error - free region for import table too far from image base: 0x%p\n", TargetImportTable);
                goto out;
            }
#endif
            
            DoOutputDebugString("InjectDllViaIAT: Allocated 0x%x bytes for new import table at 0x%p.\n", NewImportDirectorySize, TargetImportTable);
            break;
        }
        
        if (TargetImportTable)
            break;
    }

    if (TargetImportTable == NULL) 
    {
        DoOutputDebugString("InjectDllViaIAT: Failed to allocate region in target process for new import table.\n");
        goto out;
    }

    pImageDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)NewImportDirectory;
    NewImportsRVA = (DWORD)(TargetImportTable - (BYTE*)BaseAddress);

    if (StringCchCopyA((char*)NewImportDirectory + SizeOfTables, NewImportDirectorySize - SizeOfTables, DllPath))
    {
        DoOutputErrorString("InjectDllViaIAT: Failed to copy DLL path to new import directory");
        goto out;
    }
    
    // We fill our new import descriptor with required values
    pImageDescriptor->OriginalFirstThunk = NewImportsRVA + NewSizeOfImportDescriptors;
    pImageDescriptor->FirstThunk = NewImportsRVA + NewSizeOfImportDescriptors + (sizeof(IMAGE_THUNK_DATAXX) * 2);
    pImageDescriptor->Name = NewImportsRVA + SizeOfTables;

    // We will use an ordinal value of 1
    OrdinalValue = 1;
    
    // We write the ordinal value & flag to OriginalFirstThunk
    pOriginalFirstThunk = (PIMAGE_THUNK_DATAXX)(NewImportDirectory + NewSizeOfImportDescriptors);
    pOriginalFirstThunk->u1.Ordinal =  OrdinalValue | IMAGE_ORDINAL_FLAG_XX;

    // We write to FirstThunk in the same way
    pFirstThunk = pOriginalFirstThunk+2;
    pFirstThunk->u1.Ordinal = OrdinalValue | IMAGE_ORDINAL_FLAG_XX;

    // Append the original import descriptors (if any) after our created one
    if (NtHeader.IMPORT_DIRECTORY.VirtualAddress != 0) 
    {
        if (!ReadProcessMemory(ProcessHandle, (BYTE*)BaseAddress + NtHeader.IMPORT_DIRECTORY.VirtualAddress, pImageDescriptor+1, OriginalNumberOfDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR), &BytesRead)
            || BytesRead < OriginalNumberOfDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR)) 
        {
            DoOutputDebugString("InjectDllViaIAT: Failed to read import descriptors");
            RetVal = ERROR_READMEMORY;
            goto out;
        }
    }

    // Write the new table to the process
    if (!WriteProcessMemory(ProcessHandle, TargetImportTable, NewImportDirectory, NewImportDirectorySize, NULL)) 
    {
        DoOutputErrorString("InjectDllViaIAT: Failed to write new import descriptor table to target process");
        RetVal = ERROR_WRITEMEMORY;
        goto out;
    }

    // If IAT zero, set it to section that contains original import table to prevent LdrpSnapIAT failure
    if (NtHeader.IAT_DIRECTORY.VirtualAddress == 0)
    {
        NtHeader.IAT_DIRECTORY.VirtualAddress = ImportsSection.VirtualAddress;
        if (ImportsSection.Misc.VirtualSize)
            NtHeader.IAT_DIRECTORY.Size = ImportsSection.Misc.VirtualSize;
        else
            NtHeader.IAT_DIRECTORY.Size = ImportsSection.SizeOfRawData;
    }

    // Now set the import table directory entry to point to the new table
    NtHeader.IMPORT_DIRECTORY.VirtualAddress = NewImportsRVA;
    NtHeader.IMPORT_DIRECTORY.Size = NewImportDirectorySize;
    
    // Set bound imports values to zero to prevent them overriding our new import table
    NtHeader.BOUND_DIRECTORY.VirtualAddress = 0;
    NtHeader.BOUND_DIRECTORY.Size = 0;    

    // Zero out any checksum
    NtHeader.OptionalHeader.CheckSum = 0;
    
    // Set target image page permissions to allow writing of new headers
    if (!VirtualProtectEx(ProcessHandle, (BYTE*)BaseAddress, NtHeader.OptionalHeader.SizeOfHeaders, PAGE_EXECUTE_READWRITE, &dwProtect)) 
    {
        DoOutputErrorString("InjectDllViaIAT: Failed to modify memory page protection of NtHeader");
        goto out;
    }

    // Copy the new NT headers back to the target process
    if (!WriteProcessMemory(ProcessHandle, (BYTE*)BaseAddress + DosHeader.e_lfanew, &NtHeader, sizeof(NtHeader), NULL)) 
    {
        DoOutputErrorString("InjectDllViaIAT: Failed to write new NtHeader");
        RetVal = ERROR_WRITEMEMORY;
        goto out;
    }
    
    DoOutputDebugString("InjectDllViaIAT: NtHeaders written to 0x%p.\n", (BYTE*)BaseAddress + DosHeader.e_lfanew);

    // Restore original protection
    if (!VirtualProtectEx(ProcessHandle, (BYTE*)BaseAddress, NtHeader.OptionalHeader.SizeOfHeaders, dwProtect, &dwProtect))
    {
        DoOutputErrorString("InjectDllViaIAT: Failed to restore previous memory page protection");
        goto out;
    }

    RetVal = 1;
    
out:
    return RetVal;
    
}

static int InjectDll(int ProcessId, int ThreadId, const char *DllPath, BOOLEAN ForceLoad)
{
    HANDLE ProcessHandle, ThreadHandle;
    int RetVal = 0;
    
    ProcessHandle = NULL;
    ThreadHandle = NULL;
    
    if (!ProcessId)
    {
        DoOutputDebugString("InjectDll: Error, no process identifier supplied.\n");
        goto out;
    }
    
    ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    
    if (ProcessHandle == NULL) 
    {
        DoOutputErrorString("InjectDll: Failed to open process");
        RetVal = ERROR_PROCESS_OPEN;
        goto out;
    }

    // If no thread id supplied, we fetch the initial thread id
    // from the TEB's CLIENT_ID
    if (!ThreadId)
        ThreadId = GetProcessInitialThreadId(ProcessHandle);
        
    if (!ThreadId)
    {
        DoOutputDebugString("InjectDll: GetProcessInitialThreadId failed");
        ForceLoad = TRUE;
        //RetVal = ERROR_THREAD_OPEN;
        //goto out;
    }
    else
        ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);
    
    if (ThreadHandle == NULL) 
    {
        DoOutputDebugString("InjectDll: OpenThread failed");
        ForceLoad = TRUE;
        //RetVal = ERROR_THREAD_OPEN;
        //goto out;
    }
    
    // We try to use IAT patching in case this is a new process.
    // If it's not, this function is expected to fail.
    if (!ForceLoad && InjectDllViaIAT(ProcessHandle, ThreadHandle, DllPath))
        DoOutputDebugString("InjectDll: Successfully patched new process IAT.\n");
    
    // We inject via thread in any case. A new process may have its IAT patching
    // overwritten by, for example, process hollowing, so we need a fall back.
    // N.B. ForceLoad is intended for use with the debugger, not normal injection.
    RetVal = InjectDllViaThread(ProcessHandle, ThreadHandle, DllPath, ForceLoad);
    
    if (RetVal)
        DoOutputDebugString("InjectDll: Successfully injected DLL via thread.\n");
    else
        DoOutputDebugString("InjectDll: DLL injection via thread failed.\n");

out:        
    if (ProcessHandle)
        CloseHandle(ProcessHandle);
    if (ThreadHandle)
        CloseHandle(ThreadHandle);

    return RetVal;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{    
    DoOutputDebugString("CAPE loader.\n");
    
    if (__argc < 2)
        return ERROR_ARGCOUNT;
    
    if (!GrantDebugPrivileges())
        return ERROR_DEBUGPRIV;

    if (!strcmp(__argv[1], "inject")) 
    {
        // usage: loader.exe inject <pid> <tid> <dll to load>
        int ProcessId, ThreadId, ret;
        char *DllName;
        if (__argc != 6)
            return ERROR_ARGCOUNT;
        ProcessId = atoi(__argv[2]);
        ThreadId = atoi(__argv[3]);
        DllName = __argv[4];
        ret = InjectDll(ProcessId, ThreadId, DllName, FALSE);

        if (ret)
            DoOutputDebugString("Successfully injected DLL %s.\n", __argv[4]);
        else
            DoOutputDebugString("Failed to inject DLL %s.\n", __argv[4]);

        return ret;
    } 
    else if (!strcmp(__argv[1], "load")) 
    {    
        // usage: loader.exe load <binary> <commandline> <dll to load>
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        HANDLE ThreadHandle;
        int ret;
        char szCommand[2048];
        szCommand[0] = L'\0';
        
        memset(&si, 0, sizeof(si));
        memset(&pi, 0, sizeof(pi));
        si.cb = sizeof(si);
        
        StringCchCat(szCommand, sizeof(szCommand), __argv[2]);
        StringCchCat(szCommand, sizeof(szCommand), " ");
        StringCchCat(szCommand, sizeof(szCommand), __argv[3]);
        
        CreateProcess(__argv[2], szCommand, NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED, NULL, NULL, &si, &pi);
        
        ret = InjectDll(pi.dwProcessId, pi.dwThreadId, __argv[4], FALSE);
        
        if (ret)
            DoOutputDebugString("Successfully injected DLL %s.\n", __argv[4]);
        else
            DoOutputDebugString("Failed to inject DLL %s.\n", __argv[4]);

        ThreadHandle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, pi.dwThreadId);
        
        if (ThreadHandle) 
        {
            ResumeThread(ThreadHandle);
            CloseHandle(ThreadHandle);
        }
        else
            DoOutputDebugString("There was a problem resuming the new process %s.\n", __argv[2]);
        
    } 
    else if (!strcmp(__argv[1], "shellcode")) 
    {
        // usage: loader.exe shellcode <payload file>
        HANDLE hInputFile;
        LARGE_INTEGER InputFileSize;
        BYTE *PayloadBuffer = NULL;
        DWORD dwBytesRead, dwBytesToWrite;
        
        PSHELLCODE Payload;

        hInputFile = CreateFileA(__argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (!hInputFile || hInputFile == INVALID_HANDLE_VALUE)
        {
            DoOutputErrorString("Error opening input file");
            return 0;
        }

        if (!GetFileSizeEx(hInputFile, &InputFileSize))
        {
            DoOutputErrorString("Error getting file size");
            return 0;
        }

        if (InputFileSize.HighPart)
        {
            DoOutputDebugString("Input file is too big!.\n");
            return 0;
        }

        dwBytesToWrite = InputFileSize.LowPart;
        
        PayloadBuffer = (BYTE*)VirtualAlloc(NULL, InputFileSize.LowPart, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        
        if (PayloadBuffer == NULL)
        {
            DoOutputDebugString("Error allocating memory for file buffer.\n");
            return 0;
        }

        memset(PayloadBuffer, 0, InputFileSize.LowPart);
        
        if (FALSE == ReadFile(hInputFile, PayloadBuffer, InputFileSize.LowPart, &dwBytesRead, NULL))
        {
            DoOutputDebugString("ReadFile error on input file.\n");
            return 0;
        }
            
        Payload = (PSHELLCODE)PayloadBuffer;
        
        __try
        {
            Payload();
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            DoOutputDebugString("Exception executing payload at 0x%p.\n", PayloadBuffer);
        }

        free(PayloadBuffer);
        CloseHandle(hInputFile);
        return 1;
    } 
    else if (!strcmp(__argv[1], "debug")) 
    {
        // usage: loader.exe debug <binary> <commandline> <dll debugger>
        int ProcessId, ThreadId;
        int RetVal;
        HANDLE hProcess, hThread; 
        

        if (__argc != 7)
            return ERROR_ARGCOUNT;
        ProcessId = atoi(__argv[2]);
        ThreadId = atoi(__argv[3]);
    
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, ProcessId);
        if (hProcess == NULL) 
        {
            DoOutputErrorString("OpenProcess failed");
            return -18;
        }
        
        hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, ThreadId);
        if (hThread == NULL) 
        {
            DoOutputErrorString("OpenThread failed");
            return -19;
        }
    
        RetVal = InjectDll(ProcessId, ThreadId, __argv[6], TRUE);

        CloseHandle(hProcess);
        CloseHandle(hThread);
        
        return RetVal;
    } 
    else if (!strcmp(__argv[1], "debug_load")) 
    {
        // usage: loader.exe debug_load <binary> <commandline> <dll debugger>
        // called by: \analyzer\windows\lib\api\process.py::debug_inject
        // This is for the initial process, as it performs the full debugger
        // launch. "debug" is used for child processes as the parent process' 
        // monitor/debugger dll does the pipe stuff.
        int ProcessId, ThreadId;
        BOOL fSuccess, fConnected;
        int RetVal;
        CONTEXT ctx;
        DWORD cbBytesRead, cbWritten, cbReplyBytes;
        DWORD_PTR OEP, RemoteFuncAddress;
        HANDLE hPipe, hProcess, hThread; 
        char lpszPipename[MAX_PATH];
        
        if (__argc != 7)
            return ERROR_ARGCOUNT;
            
        ProcessId = atoi(__argv[2]);
        ThreadId = atoi(__argv[3]);

        memset(lpszPipename, 0, MAX_PATH*sizeof(CHAR));
        sprintf_s(lpszPipename, MAX_PATH, "\\\\.\\pipe\\CAPEpipe_%x", ProcessId);
    
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, ProcessId);
        if (hProcess == NULL) 
        {
            DoOutputErrorString("Loader: OpenProcess failed");
            return -18;
        }
        
        hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, ThreadId);
        if (hThread == NULL) 
        {
            DoOutputErrorString("Loader: OpenThread failed");
            return -19;
        }
        
        RemoteFuncAddress = 0;
        fConnected = FALSE; 
        hPipe = INVALID_HANDLE_VALUE;

        hPipe = CreateNamedPipeA
        ( 
            lpszPipename,             	// pipe name 
            PIPE_ACCESS_DUPLEX,       	// read/write access 
            PIPE_TYPE_MESSAGE |       	// message type pipe 
            PIPE_READMODE_MESSAGE |   	// message-read mode 
            PIPE_WAIT,                	// blocking mode 
            PIPE_UNLIMITED_INSTANCES, 	// max. instances  
            BUFSIZE,                  	// output buffer size 
            BUFSIZE,                  	// input buffer size 
            0,                        	// client time-out 
            NULL
        );								// default security attribute 

        if (hPipe == INVALID_HANDLE_VALUE) 
        {
            DoOutputErrorString("Loader: CreateNamedPipe failed");
            return -14;
        }
     
        RetVal = InjectDll(ProcessId, ThreadId, __argv[6], TRUE);

        // Wait for the client to connect
        fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); 
        fSuccess = FALSE;
        cbBytesRead = 0;
        
        if (fConnected) 
        { 
            DoOutputDebugString("Loader: Client connected\n");
            
            fSuccess = ReadFile
            ( 
                hPipe,        			    // handle to pipe 
                &RemoteFuncAddress,         // buffer to receive data 
                sizeof(DWORD_PTR),			// size of buffer 
                &cbBytesRead, 			    // number of bytes read 
                NULL          			    // not overlapped I/O
            );
        } 
        else 
        {
            DoOutputDebugString("Loader: The client could not connect, closing pipe.\n");
            CloseHandle(hPipe);
            return -15;
        }
        
        if (!fSuccess || cbBytesRead == 0)
        {   
            if (GetLastError() == ERROR_BROKEN_PIPE)
                DoOutputErrorString("Loader: Client disconnected");
            else
                DoOutputErrorString("Loader: ReadFile failed");
        }

        if (!RemoteFuncAddress)
        {
            DoOutputErrorString("Loader: Successfully read from pipe, however RemoteFuncAddress = 0");
            return -16;
        }
        
        DoOutputDebugString("Loader: Successfully received debugger init address: 0x%x.\n", RemoteFuncAddress);

        ctx.ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(hThread, &ctx))
        {
            DoOutputDebugString("GetThreadContext failed - FATAL\n");
            return -17;
        }

#ifndef _WIN64       
        OEP = ctx.Eax;  // eax holds eip on 32-bit
        DoOutputDebugString("GetThreadContext gives OEP=0x%x\n", ctx.Eax);
#else
        OEP = ctx.Rcx;  // rcx holds rip on 64-bit
        DoOutputDebugString("GetThreadContext gives OEP=0x%x\n", ctx.Rcx);
#endif        
        
        cbWritten = 0;
        cbReplyBytes = sizeof(DWORD_PTR);
        
        // Write the reply to the pipe. 
        fSuccess = WriteFile
        ( 
            hPipe,        		// handle to pipe 
            &OEP,				// buffer to write from 
            cbReplyBytes, 		// number of bytes to write 
            &cbWritten,   		// number of bytes written 
            NULL          		// not overlapped I/O 
        );

        if (!fSuccess || cbReplyBytes != cbWritten)
            DoOutputErrorString("Failed to send OEP via pipe");
        else
            DoOutputDebugString("Sent OEP 0x%x via pipe\n", OEP);

        if (RetVal == 1)
        {
            DoOutputDebugString("Loader: Child process created, suspended, DLL successfully injected\n");

            ctx.ContextFlags = CONTEXT_ALL;
#ifndef _WIN64       
            ctx.Eax = RemoteFuncAddress;		// eax holds new entry point
#else
            ctx.Rcx = RemoteFuncAddress;		// rcx holds new entry point
#endif        
            if (!SetThreadContext(hThread, &ctx))
                DoOutputDebugString("Failed to set new EP\n");
            else
#ifndef _WIN64       
                DoOutputDebugString("Set new EP to 0x%x\n", ctx.Eax);
#else
                DoOutputDebugString("Set new EP to 0x%x\n", ctx.Rcx);
#endif        
        }
        CloseHandle(hPipe);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        
        return 1;
        
    } 
    else if (!strcmp(__argv[1], "test")) 
    {
        // usage: loader.exe test <binary> <commandline> <dll debugger>
        PROCESS_INFORMATION pi;
        STARTUPINFOA si;
        BOOL fSuccess, fConnected;
        int RetVal;
        CONTEXT ctx;
        char DebugOutput[MAX_PATH];
        DWORD  dwThreadId, cbBytesRead, cbWritten, cbReplyBytes, ExitCode;
        DWORD_PTR OEP, RemoteFuncAddress;
        HANDLE hPipe; 
        char lpszPipename[MAX_PATH]; 
        HANDLE ThreadHandle = NULL;
        HANDLE ProcessHandle = NULL;
        RemoteFuncAddress = 0;
        fConnected = FALSE; 
        dwThreadId = 0; 
        hPipe = INVALID_HANDLE_VALUE;
        
        memset(&si, 0, sizeof(si));
        if (__argc != 5)
            return ERROR_ARGCOUNT;
        
        if (!CreateProcessA(__argv[2], __argv[3], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        {
            DoOutputErrorString("Failed to create process");
            return -6;        
        }
        else
        {
            DoOutputDebugString("CreateProcess succeeded.\n");
        }        

        memset(lpszPipename, 0, MAX_PATH*sizeof(CHAR));
        sprintf_s(lpszPipename, MAX_PATH, "\\\\.\\pipe\\CAPEpipe_%x", pi.dwProcessId);

        hPipe = CreateNamedPipeA
        ( 
            lpszPipename,             	// pipe name 
            PIPE_ACCESS_DUPLEX,       	// read/write access 
            PIPE_TYPE_MESSAGE |       	// message type pipe 
            PIPE_READMODE_MESSAGE |   	// message-read mode 
            PIPE_WAIT,                	// blocking mode 
            PIPE_UNLIMITED_INSTANCES, 	// max. instances  
            BUFSIZE,                  	// output buffer size 
            BUFSIZE,                  	// input buffer size 
            0,                        	// client time-out 
            NULL
        );								// default security attribute 

        if (hPipe == INVALID_HANDLE_VALUE) 
        {
            DoOutputErrorString("CreateNamedPipe failed");
            return -5;
        }
        else
        {
            DoOutputDebugString("CreateNamedPipe succeeded.\n");
        }
        
        RetVal = InjectDll(pi.dwProcessId, pi.dwThreadId, __argv[4], TRUE);

        DoOutputDebugString("Returned from inject, about to call ConnectNamedPipe.\n");
        
        // Wait for the client to connect; if it succeeds, 
        // the function returns a nonzero value. If the function
        // returns zero, GetLastError returns ERROR_PIPE_CONNECTED. 

        fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); 
        fSuccess = FALSE;
        cbBytesRead = 0;
        
        if (fConnected) 
        { 
            DoOutputDebugString("Client connected\n");
            
            fSuccess = ReadFile
            ( 
                hPipe,        			    // handle to pipe 
                &RemoteFuncAddress,         // buffer to receive data 
                sizeof(DWORD_PTR),			// size of buffer 
                &cbBytesRead, 			    // number of bytes read 
                NULL          			    // not overlapped I/O
            );
        } 
        else 
        {
            DoOutputDebugString("The client could not connect, closing pipe.\n");
            CloseHandle(hPipe);
            return -7;
        }
        
        if (!fSuccess || cbBytesRead == 0)
        {   
            if (GetLastError() == ERROR_BROKEN_PIPE)
                DoOutputErrorString("Client disconnected");
            else
                DoOutputErrorString("ReadFile failed");
        }

        if (!RemoteFuncAddress)
        {
            DoOutputErrorString("Successfully read from pipe, however RemoteFuncAddress = 0");
            return -8;
        }
        
        DoOutputDebugString("Successfully received debugger init address: 0x%x.\n", RemoteFuncAddress);

        ctx.ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(pi.hThread, &ctx))
        {
            DoOutputDebugString("GetThreadContext failed - FATAL\n");
            return -9;
        }

#ifndef _WIN64       
        OEP = ctx.Eax;  // eax holds eip on 32-bit
#else                 
        OEP = ctx.Rcx;  // rcx holds rip on 64-bit
#endif        
        
        memset(DebugOutput, 0, MAX_PATH*sizeof(char));
#ifndef _WIN64       
        DoOutputDebugString("GetThreadContext gives OEP=0x%x\n", ctx.Eax);
#else
        DoOutputDebugString("GetThreadContext gives OEP=0x%x\n", ctx.Rcx);
#endif        
        
        cbWritten = 0;
        cbReplyBytes = sizeof(DWORD_PTR);
        
        // Write the reply to the pipe. 
        fSuccess = WriteFile
        ( 
            hPipe,        		// handle to pipe 
            &OEP,				// buffer to write from 
            cbReplyBytes, 		// number of bytes to write 
            &cbWritten,   		// number of bytes written 
            NULL          		// not overlapped I/O 
        );
        
        if (!fSuccess || cbReplyBytes != cbWritten)
            DoOutputErrorString("Failed to send OEP via pipe");
        else
            DoOutputDebugString("Sent OEP 0x%x via pipe\n", OEP);

        if (RetVal == 1)
        {
            DoOutputDebugString("Loader: Child process created, suspended, DLL successfully injected\n");

            ctx.ContextFlags = CONTEXT_ALL;
#ifndef _WIN64       
            ctx.Eax = RemoteFuncAddress;		// eax holds new entry point
#else
            ctx.Rcx = RemoteFuncAddress;		// rcx holds new entry point
#endif        
            if (!SetThreadContext(pi.hThread, &ctx))
                DoOutputDebugString("Failed to set new EP\n");
            else
#ifndef _WIN64       
                DoOutputDebugString("Set new EP to 0x%x\n", ctx.Eax);
#else
                DoOutputDebugString("Set new EP to 0x%x\n", ctx.Rcx);
#endif        
        }
        
        Sleep(1000);
        
        CloseHandle(hPipe);
        
        ResumeThread(pi.hThread);
        
        Sleep(5000);
        
        if (GetExitCodeProcess(pi.hProcess, &ExitCode))
        {
            DoOutputDebugString("Exit code: 0x%x\n", ExitCode);
        }
        
        return 1;
    }
	else if (!strcmp(__argv[1], "pipe")) 
    {
		// usage: loader.exe pipe <pipe name> <dll to load>
		HANDLE PipeHandle;
		char PipeName[BUFSIZE];
        int LastPid = 0;

		if (__argc != 4)
			return ERROR_ARGCOUNT;

		sprintf_s(PipeName, sizeof(PipeName)-1, "\\\\.\\PIPE\\%s", __argv[2]);

		while (1) 
        {
            PipeHandle = CreateNamedPipeA(PipeName, PIPE_ACCESS_DUPLEX,
				PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
				PIPE_UNLIMITED_INSTANCES,
				PIPEBUFSIZE,
				PIPEBUFSIZE,
				0,
				NULL);
			
            if (ConnectNamedPipe(PipeHandle, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) 
            {
				char buf[PIPEBUFSIZE];
				char response[PIPEBUFSIZE];
				int response_len = 0;
				int bytes_read = 0;
				int BytesWritten = 0;
                
				memset(buf, 0, sizeof(buf));
				memset(response, 0, sizeof(response));
				
                ReadFile(PipeHandle, buf, sizeof(buf), &bytes_read, NULL);
                DoOutputDebugString("%s\n", buf);
				if (!strncmp(buf, "PROCESS:", 8)) {
					int ProcessId = -1, ThreadId = -1;
					char *p;
					if ((p = strchr(buf, ','))) {
						*p = '\0';
						ProcessId = atoi(&buf[10]); // skipping the '0:' or '1:' suspended flag
						ThreadId = atoi(p + 1);
					}
					else {
						ProcessId = atoi(&buf[10]);
					}
					if (ProcessId && ThreadId && ProcessId != LastPid)
                    {
                        DoOutputDebugString("About to call InjectDll on process %d, thread 5%d.\n", ProcessId, ThreadId);
                        if (InjectDll(ProcessId, ThreadId, __argv[3], FALSE))
                            LastPid = ProcessId; 
                    }
				}
				WriteFile(PipeHandle, response, response_len, &BytesWritten, NULL);
				CloseHandle(PipeHandle);
			}
		}
	}
	return ERROR_MODE;
}
