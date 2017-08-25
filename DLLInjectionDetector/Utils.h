#pragma once

class CUtils
{
	public:
		static PVOID GetModuleAddressFromName(const wchar_t* c_wszName);
		static bool  IsLoadedAddress(DWORD dwAddress);

		static PVOID DetourFunc(BYTE *src, const BYTE *dst, const int len);
		static DWORD FindPattern(DWORD dwAddress, DWORD dwLen, BYTE *bMask, char * szMask);

		static bool  IsSuspendedThread(DWORD dwThreadId);

		static DWORD GetThreadOwnerProcessId(DWORD dwThreadID);
};

