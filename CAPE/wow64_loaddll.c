/*
CAPE - Config And Payload Extraction
Copyright(C) 2015, 2016 Context Information Security. (kevin.oreilly@contextis.com)

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
#ifndef _WIN64
#include "w64wow64\w64wow64.h"
// Adapted from W64oWoW64 https://github.com/georgenicolaou/W64oWoW64 
// by George Nicolaou, itself based upon ReWolf's wow64ext library:
// https://github.com/rwfpl/rewolf-wow64ext

typedef struct _UNICODE_STRING {
   USHORT Length;
   USHORT MaximumLength;
   PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef NTSTATUS(WINAPI * _RtlInitUnicodeStringEx)
(
  _Out_    PUNICODE_STRING  DestinationString,
  _In_opt_ PCWSTR           pszSrc,
  _In_     DWORD            dwFlags
);

typedef VOID(__stdcall *_RtlInitUnicodeString)(
   PUNICODE_STRING          DestinationString,
   PCWSTR                   SourceString
);

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

BOOL WoW64Detected;

//**************************************************************************************
extern BOOL WoW64LoadDll(char* DllPath)
//**************************************************************************************
{
    IsWow64Process(GetCurrentProcess(), &WoW64Detected);
    if (WoW64Detected == FALSE)
    {
        DoOutputDebugString("WoW64LoadDll: WoW64 not detected.\n");
        return FALSE;
    }

    if (InitializeW64oWoW64() == FALSE)
    {
        DoOutputDebugString("WoW64LoadDll: InitializeW64oWoW64 failed.\n");
        return FALSE;
    }

	DoOutputDebugString("WoW64LoadDll: InitializeW64oWoW64 success.\n");
	
	DWORD64 DllImageBase = LoadLibrary64A(DllPath);
	
    if (DllImageBase == (DWORD64)NULL)
    {
        DoOutputDebugString("WoW64LoadDll: Loading %s failed.\n", DllPath);
        return FALSE;
    }

	DoOutputDebugString("WoW64LoadDll: %s loaded at 0x%x.\n", DllPath, DllImageBase);

    return TRUE;
}
#endif