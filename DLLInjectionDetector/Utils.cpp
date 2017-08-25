#include "main.h"
#include "Utils.h"
#include "ThreadEnumerator.h"

PVOID CUtils::DetourFunc(BYTE *src, const BYTE *dst, const int len)
{
	BYTE *jmp = (BYTE*)malloc(len + 5);

	DWORD dwback;
	VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &dwback);

	memcpy(jmp, src, len);
	jmp += len;

	jmp[0] = 0xE9;
	//relative address from trampoline to orig function + 5
	*(DWORD*)(jmp + 1) = (DWORD)(src + len - jmp) - 5;

	src[0] = 0xE9;
	*(DWORD*)(src + 1) = (DWORD)(dst - src) - 5;

	VirtualProtect(src, len, dwback, &dwback);

	//address to trampoline
	return (jmp - len);
}

PVOID CUtils::GetModuleAddressFromName(const wchar_t* c_wszName)
{
	PPEB pPEB = (PPEB)__readfsdword(0x30);
	PLDR_DATA_TABLE_ENTRY Current = NULL;
	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InMemoryOrderModuleList.Flink;

	while (CurrentEntry != &pPEB->Ldr->InMemoryOrderModuleList && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		// printf("%ls -> %p\n", Current->FullDllName.Buffer, Current->DllBase);
		if (wcsstr(Current->FullDllName.Buffer, c_wszName))
			return Current->DllBase;

		CurrentEntry = CurrentEntry->Flink;
	}
	return nullptr;
}
bool CUtils::IsLoadedAddress(DWORD dwAddress)
{
	PPEB pPEB = (PPEB)__readfsdword(0x30);
	PLDR_DATA_TABLE_ENTRY Current = NULL;
	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InMemoryOrderModuleList.Flink;

	while (CurrentEntry != &pPEB->Ldr->InMemoryOrderModuleList && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (dwAddress == (DWORD)Current->DllBase)
			return true;

		CurrentEntry = CurrentEntry->Flink;
	}
	return false;
}

BOOL bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return FALSE;
	return (*szMask) == NULL;
}
DWORD CUtils::FindPattern(DWORD dwAddress, DWORD dwLen, BYTE *bMask, char * szMask)
{
	for (DWORD i = 0; i < dwLen; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (DWORD)(dwAddress + i);
	return 0;
}

DWORD CUtils::GetThreadOwnerProcessId(DWORD dwThreadID)
{
	auto hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (!hSnap || hSnap == INVALID_HANDLE_VALUE) 
		return 0;

	THREADENTRY32 ti = { 0 };
	ti.dwSize = sizeof(ti);

	if (Thread32First(hSnap, &ti))
	{
		do {
			if (dwThreadID == ti.th32ThreadID) {
				CloseHandle(hSnap);
				return ti.th32OwnerProcessID;
			}
		} while (Thread32Next(hSnap, &ti));
	}

	CloseHandle(hSnap);
	return 0;
}