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
#include <stdio.h>
#include "..\ntapi.h"
#include <psapi.h>
#include <distorm.h>
#include "..\misc.h"
#include "..\hooking.h"
#include "..\log.h"
#include "Debugger.h"
#include "CAPE.h"

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void TestDoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);
extern PVOID get_process_image_base(HANDLE process_handle);

void GetThreadContextHandler(DWORD Pid, LPCONTEXT Context)
{
    if (Context && Context->ContextFlags & CONTEXT_CONTROL)
    {
        struct InjectionInfo *CurrentInjectionInfo = GetInjectionInfo(Pid);
#ifdef _WIN64
        if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == Pid)
            CurrentInjectionInfo->StackPointer = (LPVOID)Context->Rsp;
#else
        if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == Pid)
            CurrentInjectionInfo->StackPointer = (LPVOID)Context->Esp;
#endif
    }
}

void SetThreadContextHandler(DWORD Pid, const CONTEXT *Context)
{
	if (Context && Context->ContextFlags & CONTEXT_CONTROL)
    {
        struct InjectionInfo *CurrentInjectionInfo = GetInjectionInfo(Pid);
#ifdef _WIN64
        if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == Pid)
            CurrentInjectionInfo->EntryPoint = Context->Rcx - CurrentInjectionInfo->ImageBase;  // rcx holds ep on 64-bit
           
        if (Context->Rip == (DWORD_PTR)GetProcAddress(GetModuleHandle("ntdll"), "NtMapViewOfSection"))
            DoOutputDebugString("SetThreadContextHandler: Hollow process entry point set to NtMapViewOfSection (process %d).\n", Pid);
        else
            DoOutputDebugString("SetThreadContextHandler: Hollow process entry point reset via NtSetContextThread to 0x%p (process %d).\n", CurrentInjectionInfo->EntryPoint, Pid);
#else
        if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == Pid)
            CurrentInjectionInfo->EntryPoint = Context->Eax - CurrentInjectionInfo->ImageBase;  // eax holds ep on 32-bit

        if (Context->Eip == (DWORD)GetProcAddress(GetModuleHandle("ntdll"), "NtMapViewOfSection"))
            DoOutputDebugString("SetThreadContextHandler: Hollow process entry point set to NtMapViewOfSection (process %d).\n", Pid);
        else
            DoOutputDebugString("SetThreadContextHandler: Hollow process entry point reset via NtSetContextThread to 0x%p (process %d).\n", CurrentInjectionInfo->EntryPoint, Pid);
#endif
    }
}

void ResumeThreadHandler(DWORD Pid)
{
    struct InjectionInfo *CurrentInjectionInfo = GetInjectionInfo(Pid);

    if (!CurrentInjectionInfo)
    {
        DoOutputDebugString("ResumeThreadHandler: CurrentInjectionInfo 0x%x (Pid %d).\n", CurrentInjectionInfo, Pid);
        return;
    }
    
    if (CurrentInjectionInfo->ImageBase && CurrentInjectionInfo->WriteDetected && CurrentInjectionInfo->ImageDumped == FALSE)
    {
        CapeMetaData->DumpType = INJECTION_PE;
        CapeMetaData->TargetPid = Pid;
        
        DoOutputDebugString("ResumeThreadHandler: Dumping hollowed process %d, image base 0x%p.\n", Pid, CurrentInjectionInfo->ImageBase);
        
        CurrentInjectionInfo->ImageDumped = DumpProcess(CurrentInjectionInfo->ProcessHandle, (PVOID)CurrentInjectionInfo->ImageBase);
        
        if (CurrentInjectionInfo->ImageDumped)
        {
            DoOutputDebugString("ResumeThreadHandler: Dumped PE image from buffer.\n");
        }
        else
            DoOutputDebugString("ResumeThreadHandler: Failed to dump PE image from buffer.\n");
    }
    
    DumpSectionViewsForPid(Pid);
}

void CreateProcessHandler(LPWSTR lpApplicationName, LPWSTR lpCommandLine, LPPROCESS_INFORMATION lpProcessInformation)
{
    WCHAR TargetProcess[MAX_PATH];	
    struct InjectionInfo *CurrentInjectionInfo;    

    // Create 'injection info' struct for the newly created process
    CurrentInjectionInfo = CreateInjectionInfo(lpProcessInformation->dwProcessId);
    
    if (CurrentInjectionInfo == NULL)
    {
        DoOutputDebugString("CreateProcessHandler: Failed to create injection info for new process %d, ImageBase: 0x%p", lpProcessInformation->dwProcessId, CurrentInjectionInfo->ImageBase);
        return;
    }
    
    CurrentInjectionInfo->ProcessHandle = lpProcessInformation->hProcess;
    CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(lpProcessInformation->hProcess);
    CurrentInjectionInfo->EntryPoint = (DWORD_PTR)NULL;
    CurrentInjectionInfo->ImageDumped = FALSE;

    CapeMetaData->TargetProcess = (char*)malloc(MAX_PATH);
    memset(TargetProcess, 0, MAX_PATH*sizeof(WCHAR));

    if (lpApplicationName)
        _snwprintf(TargetProcess, MAX_PATH, L"%s", lpApplicationName);
    else if (lpCommandLine)
    {
        DoOutputDebugString("CreateProcessHandler: using lpCommandLine: %ws.\n", lpCommandLine);
        if (*lpCommandLine == L'\"')
            wcsncpy_s(TargetProcess, MAX_PATH, lpCommandLine+1, (rsize_t)((wcschr(lpCommandLine+1, '\"') - lpCommandLine)-1));
        else 
        {
            if (wcschr(lpCommandLine, ' '))
                wcsncpy_s(TargetProcess, MAX_PATH, lpCommandLine, (rsize_t)((wcschr(lpCommandLine, ' ') - lpCommandLine)+1));
            else 
                wcsncpy_s(TargetProcess, MAX_PATH, lpCommandLine, wcslen(lpCommandLine)+1);
        }
    }

    WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, (LPCWSTR)TargetProcess, (int)wcslen(TargetProcess)+1, CapeMetaData->TargetProcess, MAX_PATH, NULL, NULL);
    
    DoOutputDebugString("CreateProcessHandler: Injection info set for new process %d, ImageBase: 0x%p", CurrentInjectionInfo->ProcessId, CurrentInjectionInfo->ImageBase);
}

void OpenProcessHandler(HANDLE ProcessHandle, DWORD Pid)
{
	struct InjectionInfo *CurrentInjectionInfo;
    DWORD BufferSize = MAX_PATH;
    char DevicePath[MAX_PATH];
    unsigned int PathLength;

    CurrentInjectionInfo = GetInjectionInfo(Pid);
    
    if (CurrentInjectionInfo == NULL)
    {   // First call for this process, create new info
        CurrentInjectionInfo = CreateInjectionInfo(Pid);
        
        DoOutputDebugString("OpenProcessHandler: Injection info created for Pid %d.\n", Pid);
    
        if (CurrentInjectionInfo == NULL)
        {
            DoOutputDebugString("OpenProcessHandler: Error - cannot create new injection info.\n");
        }
        else
        {
            CurrentInjectionInfo->ProcessHandle = ProcessHandle;
            CurrentInjectionInfo->EntryPoint = (DWORD_PTR)NULL;
            CurrentInjectionInfo->ImageDumped = FALSE;
            CapeMetaData->TargetProcess = (char*)malloc(BufferSize);

            CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(ProcessHandle);

            if (CurrentInjectionInfo->ImageBase)
                DoOutputDebugString("OpenProcessHandler: Image base for process %d (handle 0x%x): 0x%p.\n", Pid, ProcessHandle, CurrentInjectionInfo->ImageBase);

            PathLength = GetProcessImageFileName(ProcessHandle, DevicePath, BufferSize);

            if (!PathLength)
            {
                DoOutputErrorString("OpenProcessHandler: Error obtaining target process name");
                _snprintf(CapeMetaData->TargetProcess, BufferSize, "Error obtaining target process name");
            }
            else if (!TranslatePathFromDeviceToLetter(DevicePath, CapeMetaData->TargetProcess, &BufferSize)) 
                DoOutputErrorString("OpenProcessHandler: Error translating target process path");                
        }
    }
    else if (CurrentInjectionInfo->ImageBase == (DWORD_PTR)NULL)
    {
        CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(ProcessHandle);

        if (CurrentInjectionInfo->ImageBase)
            DoOutputDebugString("OpenProcessHandler: Image base for process %d (handle 0x%x): 0x%p.\n", Pid, ProcessHandle, CurrentInjectionInfo->ImageBase);
    }
}

void ResumeProcessHandler(HANDLE ProcessHandle, DWORD Pid)
{
	struct InjectionInfo *CurrentInjectionInfo;

    CurrentInjectionInfo = GetInjectionInfo(Pid);
    
    if (CurrentInjectionInfo)
    {
        if (CurrentInjectionInfo->ImageBase && CurrentInjectionInfo->WriteDetected && CurrentInjectionInfo->ImageDumped == FALSE)
        {
            SetCapeMetaData(INJECTION_PE, Pid, ProcessHandle, NULL);
            
            DoOutputDebugString("ResumeProcessHandler: Dumping hollowed process %d, image base 0x%p.\n", Pid, CurrentInjectionInfo->ImageBase);
            
            CurrentInjectionInfo->ImageDumped = DumpProcess(ProcessHandle, (PVOID)CurrentInjectionInfo->ImageBase);
            
            if (CurrentInjectionInfo->ImageDumped)
            {
                DoOutputDebugString("ResumeProcessHandler: Dumped PE image from buffer.\n");
            }
            else
                DoOutputDebugString("ResumeProcessHandler: Failed to dump PE image from buffer.\n");
        }

        DumpSectionViewsForPid(Pid);
    }
}

void MapSectionViewHandler(HANDLE ProcessHandle, HANDLE SectionHandle, PVOID BaseAddress, SIZE_T ViewSize)
{
	struct InjectionInfo *CurrentInjectionInfo;
    struct InjectionSectionView *CurrentSectionViewInfo;
    char DevicePath[MAX_PATH];
    unsigned int PathLength;
    DWORD BufferSize = MAX_PATH;
	
    DWORD Pid = pid_from_process_handle(ProcessHandle);
    
    CurrentInjectionInfo = GetInjectionInfo(Pid);

    if (Pid == GetCurrentProcessId())
    {
        PINJECTIONSECTIONVIEW CurrentSectionView = GetSectionView(SectionHandle);
        
        if (!CurrentSectionView)
        {
            AddSectionView(SectionHandle, BaseAddress, ViewSize);
            DoOutputDebugString("MapSectionViewHandler: Added section view with handle 0x%x and local view 0x%p to global list.\n", SectionHandle, BaseAddress);
        }
        else
        {
            if (CurrentSectionView->LocalView != BaseAddress)
            {
                CurrentSectionView->LocalView = BaseAddress;
                CurrentSectionView->ViewSize = ViewSize;
                DoOutputDebugString("MapSectionViewHandler: Updated local view to 0x%p for section view with handle 0x%x.\n", BaseAddress, SectionHandle);
            }
        }
    }
    else if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == Pid)
    {
        CurrentSectionViewInfo = AddSectionView(SectionHandle, BaseAddress, ViewSize);

        if (CurrentSectionViewInfo)
        {
	        CurrentSectionViewInfo->TargetProcessId = Pid;
            DoOutputDebugString("MapSectionViewHandler: Added section view with handle 0x%x to target process %d.\n", SectionHandle, Pid);
        }
        else
        {
            DoOutputDebugString("MapSectionViewHandler: Error, failed to add section view with handle 0x%x and target process %d.\n", SectionHandle, Pid);
        }
    }    
    else if (!CurrentInjectionInfo && Pid != GetCurrentProcessId())
    {
        CurrentInjectionInfo = CreateInjectionInfo(Pid);
        
        if (CurrentInjectionInfo == NULL)
        {
            DoOutputDebugString("MapSectionViewHandler: Cannot create new injection info - error.\n");
        }
        else
        {
            CurrentInjectionInfo->ProcessHandle = ProcessHandle;
            CurrentInjectionInfo->ProcessId = Pid;
            CurrentInjectionInfo->EntryPoint = (DWORD_PTR)NULL;
            CurrentInjectionInfo->ImageDumped = FALSE;
            CapeMetaData->TargetProcess = (char*)malloc(BufferSize);

            CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(ProcessHandle);

            if (CurrentInjectionInfo->ImageBase)
                DoOutputDebugString("MapSectionViewHandler: Image base for process %d (handle 0x%x): 0x%p.\n", Pid, ProcessHandle, CurrentInjectionInfo->ImageBase);

            PathLength = GetProcessImageFileName(ProcessHandle, DevicePath, BufferSize);

            if (!PathLength)
            {
                DoOutputErrorString("MapSectionViewHandler: Error obtaining target process name");
                _snprintf(CapeMetaData->TargetProcess, BufferSize, "Error obtaining target process name");
            }
            else if (!TranslatePathFromDeviceToLetter(DevicePath, CapeMetaData->TargetProcess, &BufferSize)) 
                DoOutputErrorString("MapSectionViewHandler: Error translating target process path");
                
            CurrentSectionViewInfo = AddSectionView(SectionHandle, BaseAddress, ViewSize);

            if (CurrentSectionViewInfo)
            {
                CurrentSectionViewInfo->TargetProcessId = Pid;
                DoOutputDebugString("MapSectionViewHandler: Added section view with handle 0x%x to target process %d.\n", SectionHandle, Pid);
            }
            else
                DoOutputDebugString("MapSectionViewHandler: Error, failed to add section view with handle 0x%x and target process %d.\n", SectionHandle, Pid);
        }
    }
}

void UnmapSectionViewHandler(PVOID BaseAddress)
{
    PINJECTIONSECTIONVIEW CurrentSectionView; 

    CurrentSectionView = SectionViewList;

    while (CurrentSectionView)
    {
        if (CurrentSectionView->TargetProcessId && CurrentSectionView->LocalView == BaseAddress)
        {
            DoOutputDebugString("UnmapSectionViewHandler: Attempt to unmap view at 0x%p, dumping.\n", BaseAddress);
            CapeMetaData->DumpType = INJECTION_PE;
            CapeMetaData->TargetPid = CurrentSectionView->TargetProcessId;
            DumpSectionView(CurrentSectionView);
        }

        CurrentSectionView = CurrentSectionView->NextSectionView;
    }
}

void WriteMemoryHandler(HANDLE ProcessHandle, LPVOID BaseAddress, LPCVOID Buffer, SIZE_T NumberOfBytesWritten)
{
	DWORD Pid;
	struct InjectionInfo *CurrentInjectionInfo;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;

	Pid = pid_from_process_handle(ProcessHandle);
    
    CurrentInjectionInfo = GetInjectionInfo(Pid);
    
    if (!CurrentInjectionInfo || CurrentInjectionInfo->ProcessId != Pid)
        return;

    if (NumberOfBytesWritten == 0)
        return;

    CurrentInjectionInfo->WriteDetected = TRUE;
    
    // Check if we have a valid DOS and PE header at the beginning of Buffer
    if (IsDisguisedPEHeader((PVOID)Buffer))
    {
        pDosHeader = (PIMAGE_DOS_HEADER)((char*)Buffer);
        
        pNtHeader = (PIMAGE_NT_HEADERS)((char*)Buffer + pDosHeader->e_lfanew);
        
        CurrentInjectionInfo->ImageBase = (DWORD_PTR)BaseAddress;
        
        DoOutputDebugString("WriteMemoryHandler: Executable binary injected into process %d (ImageBase 0x%x)\n", Pid, CurrentInjectionInfo->ImageBase);

        if (CurrentInjectionInfo->ImageDumped == FALSE)
        {
            SetCapeMetaData(INJECTION_PE, Pid, ProcessHandle, NULL);

            CurrentInjectionInfo->ImageDumped = DumpModuleInCurrentProcess((PVOID)Buffer);
            
            if (CurrentInjectionInfo->ImageDumped)
            {
                CurrentInjectionInfo->BufferBase = (LPVOID)Buffer;
                CurrentInjectionInfo->BufferSizeOfImage = pNtHeader->OptionalHeader.SizeOfImage;
                DoOutputDebugString("WriteMemoryHandler: Dumped PE image from buffer at 0x%x, SizeOfImage 0x%x.\n", Buffer, CurrentInjectionInfo->BufferSizeOfImage);
            }
            else
            {
                DoOutputDebugString("WriteMemoryHandler: Failed to dump PE image from buffer, attempting raw dump.\n");
                
                CapeMetaData->DumpType = INJECTION_SHELLCODE;
                CapeMetaData->TargetPid = Pid;
                if (DumpMemory((LPVOID)Buffer, NumberOfBytesWritten))
                    DoOutputDebugString("WriteMemoryHandler: Dumped malformed PE image from buffer.");
                else
                    DoOutputDebugString("WriteMemoryHandler: Failed to dump malformed PE image from buffer.");                    
            }
        }                    
    }
    else
    {   
        if (NumberOfBytesWritten > 0x10)    // We assign some lower limit
        {
            if (CurrentInjectionInfo->BufferBase && Buffer > CurrentInjectionInfo->BufferBase && 
                Buffer < (LPVOID)((UINT_PTR)CurrentInjectionInfo->BufferBase + CurrentInjectionInfo->BufferSizeOfImage) && CurrentInjectionInfo->ImageDumped == TRUE)
            {   
                // Looks like a previously dumped PE image is being written a section at a time to the target process.
                // We don't want to dump these writes.
                DoOutputDebugString("WriteMemoryHandler: injection of section of PE image which has already been dumped.\n");
            }
            else
            {
                DoOutputDebugString("WriteMemoryHandler: shellcode at 0x%p (size 0x%x) injected into process %d.\n", Buffer, NumberOfBytesWritten, Pid);
            
                // dump injected code/data
                CapeMetaData->DumpType = INJECTION_SHELLCODE;
                CapeMetaData->TargetPid = Pid;
                if (DumpMemory((LPVOID)Buffer, NumberOfBytesWritten))
                    DoOutputDebugString("WriteMemoryHandler: Dumped injected code/data from buffer.");
                else
                    DoOutputDebugString("WriteMemoryHandler: Failed to dump injected code/data from buffer.");
            }
        }
    }
}
