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
#include "..\hooking.h"
#include "..\log.h"
#include "CAPE.h"

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);
extern int DumpMemory(LPVOID Buffer, SIZE_T Size);
extern int DumpPE(LPVOID Buffer);

BOOL ConfigDumped;
unsigned int memcpy_count;

HOOKDEF(void, WINAPIV, memcpy,
   void *dest,
   const void *src,
   size_t count
) 
{
	int ret = 0;	// this is needed for LOQ_void

	Old_memcpy(dest, src, count);
	
    if (count > 0xa00)
        LOQ_void("misc", "bi", "DestinationBuffer", count, dest, "count", count);
    
	if (memcpy_count == 0)
		ConfigDumped = FALSE;
	
    memcpy_count++;
	
	if (!ConfigDumped &&
    (
		count == 0xae4  || 
		count == 0xbe4  || 
        count == 0x150c ||
        count == 0x1510 ||
        count == 0x1516 ||
        count == 0x170c ||
		count == 0x1b18 ||
        count == 0x1d18 ||
        count == 0x2540 ||
        count == 0x254c ||
		count == 0x2d58 || 
		count == 0x36a4 ||
        count == 0x4ea4 
        //count > 0xa00 &&              //fuzzy matching
		//count < 0x5000)               //fuzzy matching
	))
    {
		DoOutputDebugString("PlugX config detected (#%d, size 0x%d), dumping.\n", memcpy_count, count);
        
        CapeMetaData->DumpType = PLUGX_CONFIG;

        DumpMemory((BYTE*)src, count);        

        ConfigDumped = TRUE;
    }
	
	return;
}

HOOKDEF(NTSTATUS, WINAPI, RtlDecompressBuffer,
	__in USHORT CompressionFormat,
	__out PUCHAR UncompressedBuffer,
	__in ULONG UncompressedBufferSize,
	__in PUCHAR CompressedBuffer,
	__in ULONG CompressedBufferSize,
	__out PULONG FinalUncompressedSize
) {
	long e_lfanew;
    PBYTE PEImage;
    PIMAGE_NT_HEADERS pNtHeader;

	NTSTATUS ret = Old_RtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize,
		CompressedBuffer, CompressedBufferSize, FinalUncompressedSize);

    if ((ret == STATUS_SUCCESS || ret == STATUS_BAD_COMPRESSION_BUFFER) && (*FinalUncompressedSize > 0))
	//	There are samples that return STATUS_BAD_COMPRESSION_BUFFER but still continue
	{
		// Check if we have a 'PlugX' sig where they overwrite DOS and PE headers with XV
		if (*(WORD*)UncompressedBuffer == PLUGX_SIGNATURE)
		{
			DoOutputDebugString("PlugX payload detected.\n");
			
			e_lfanew = *(long*)(UncompressedBuffer+0x3c);
		
			if (*(DWORD*)(UncompressedBuffer+e_lfanew) == PLUGX_SIGNATURE)
			{
                // We want to dump the file out with fixed PE header (for e.g. disassembly etc)				
                PEImage = (BYTE*)malloc(UncompressedBufferSize);
                memcpy(PEImage, UncompressedBuffer, UncompressedBufferSize);

                *(WORD*)PEImage = IMAGE_DOS_SIGNATURE;
                *(DWORD*)(PEImage+e_lfanew) = IMAGE_NT_SIGNATURE;

                CapeMetaData->DumpType = PLUGX_PAYLOAD;
                
                DumpPE(PEImage);
                
                free(PEImage);

                if (ret == STATUS_SUCCESS)
                    DoOutputDebugString("Dumped PlugX payload.\n");
				else
                    DoOutputDebugString("Dumped PlugX payload with BAD COMPRESSION BUFFER - maybe incomplete/bloated.\n");
			}
			else
			{
                DoOutputDebugString("PlugX signature detected at MZ but not PE, aborting dump.\n");
			}
		}
		
		// Check if we have a valid DOS and PE header at the beginning of UncompressedBuffer
		else if (*(WORD*)UncompressedBuffer == IMAGE_DOS_SIGNATURE)
		{
			DoOutputDebugString("Executable binary detected.\n");
			
			e_lfanew = *(long*)(UncompressedBuffer+0x3c);
		
			if ((unsigned int)e_lfanew>PE_HEADER_LIMIT)
			{
				// This check is possibly not appropriate here
				// As long as we've got what's been compressed
			}
				
			if (*(DWORD*)(UncompressedBuffer+e_lfanew) == IMAGE_NT_SIGNATURE)
			{
                pNtHeader = (PIMAGE_NT_HEADERS)(UncompressedBuffer+e_lfanew);

                CapeMetaData->DumpType = PLUGX_PAYLOAD;
                
                DumpPE(UncompressedBuffer);
                
                DoOutputDebugString("Dumped PE module.\n");
			}
		}
	}
        
	LOQ_ntstatus("misc", "pch", "UncompressedBufferAddress", UncompressedBuffer, "UncompressedBuffer",
		ret ? 0 : *FinalUncompressedSize, UncompressedBuffer, "UncompressedBufferLength", ret ? 0 : *FinalUncompressedSize);

    return ret;
}
