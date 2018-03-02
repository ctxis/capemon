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
extern BOOL DumpPEsInRange(LPVOID Buffer, SIZE_T Size);


HOOKDEF(NTSTATUS, WINAPI, RtlDecompressBuffer,
	__in USHORT CompressionFormat,
	__out PUCHAR UncompressedBuffer,
	__in ULONG UncompressedBufferSize,
	__in PUCHAR CompressedBuffer,
	__in ULONG CompressedBufferSize,
	__out PULONG FinalUncompressedSize
) {
	NTSTATUS ret = Old_RtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize,
		CompressedBuffer, CompressedBufferSize, FinalUncompressedSize);

	//	There are samples that return STATUS_BAD_COMPRESSION_BUFFER but still continue
    if ((ret == STATUS_BAD_COMPRESSION_BUFFER) && (*FinalUncompressedSize > 0)) {
        DoOutputDebugString("RtlDecompressBuffer hook: Checking for PE image(s) despite STATUS_BAD_COMPRESSION_BUFFER.\n", UncompressedBuffer, *FinalUncompressedSize);
        if (!DumpPEsInRange(UncompressedBuffer, UncompressedBufferSize))
        {   // If this fails let's try our own buffer
            NTSTATUS NewRet;
            PUCHAR CapeBuffer = NULL;
            ULONG NewUncompressedBufferSize = UncompressedBufferSize;
            do
            {
                ULONG UncompressedSize;

                if (CapeBuffer) {
                    if (DumpPEsInRange(CapeBuffer, NewUncompressedBufferSize)) {
                        DoOutputDebugString("RtlDecompressBuffer hook: Dumped PE file(s) from new buffer.\n");
                        break;
                    }
                    free(CapeBuffer);
                }
                    
                NewUncompressedBufferSize += UncompressedBufferSize;
                CapeBuffer = (PUCHAR)malloc(NewUncompressedBufferSize);
                
                if (!CapeBuffer) {
                    DoOutputDebugString("RtlDecompressBuffer hook: Failed to allocate new buffer.\n");
                    break;
                }
                else 
                {
                    DoOutputDebugString("RtlDecompressBuffer hook: Allocated new buffer of 0x%x bytes.\n", NewUncompressedBufferSize);
                    NewRet = Old_RtlDecompressBuffer(CompressionFormat, CapeBuffer, NewUncompressedBufferSize,
                        CompressedBuffer, CompressedBufferSize, &UncompressedSize);
                }
            }
            // Most decompressions should succeed in under 0x10 times original uncompressed buffer size
            while (NewRet == STATUS_BAD_COMPRESSION_BUFFER && NewUncompressedBufferSize < (UncompressedBufferSize * 0x10)); 

            if (NT_SUCCESS(NewRet)) {
                if (DumpPEsInRange(UncompressedBuffer, *FinalUncompressedSize))
                    DoOutputDebugString("RtlDecompressBuffer hook: Dumped PE file(s) from new buffer.\n");
            }
            else
                DoOutputErrorString("RtlDecompressBuffer hook: Failed to decompress to new buffer");
            
            if (CapeBuffer)
                free(CapeBuffer);
        }
        LOQ_ntstatus("misc", "pch", "UncompressedBufferAddress", UncompressedBuffer, "UncompressedBuffer",
            *FinalUncompressedSize, UncompressedBuffer, "UncompressedBufferLength", *FinalUncompressedSize);
	}
    else if (NT_SUCCESS(ret)) {
        DoOutputDebugString("RtlDecompressBuffer hook: scanning region 0x%x size 0x%x for PE image(s).\n", UncompressedBuffer, *FinalUncompressedSize);
		DumpPEsInRange(UncompressedBuffer, *FinalUncompressedSize);
        LOQ_ntstatus("misc", "pch", "UncompressedBufferAddress", UncompressedBuffer, "UncompressedBuffer",
            *FinalUncompressedSize, UncompressedBuffer, "UncompressedBufferLength", *FinalUncompressedSize);
    }
    else
        LOQ_ntstatus("misc", "pch", "UncompressedBufferAddress", UncompressedBuffer, "UncompressedBuffer",
            0, UncompressedBuffer, "UncompressedBufferLength", 0);
        
    return ret;
}
