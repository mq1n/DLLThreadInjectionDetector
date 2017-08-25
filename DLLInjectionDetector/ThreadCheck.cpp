#include "main.h"
#include "Utils.h"

typedef void(*LdrInitializeThunk)(PCONTEXT NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
static LdrInitializeThunk LdrInitializeThunk_ = nullptr;


typedef NTSTATUS(WINAPI* lpNtQueryInformationThread)(HANDLE, LONG, PVOID, ULONG, PULONG);
void LdrInitializeThunk_t(PCONTEXT NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	auto GetThreadStartAddress = [](HANDLE hThread) -> DWORD {
		auto NtQueryInformationThread = (lpNtQueryInformationThread)GetProcAddress(LoadLibraryA("ntdll"), "NtQueryInformationThread");
		assert(NtQueryInformationThread);

		DWORD dwCurrentThreadAddress = 0;
		NtQueryInformationThread(hThread, 9 /* ThreadQuerySetWin32StartAddress */, &dwCurrentThreadAddress, sizeof(dwCurrentThreadAddress), NULL);
		return dwCurrentThreadAddress;
	};

	auto dwStartAddress = GetThreadStartAddress(NtCurrentThread);
	printf("[*] A thread attached to process! Start address: %p\n", (void*)dwStartAddress);

	auto dwThreadId = GetThreadId(NtCurrentThread);
	printf("\t* Thread: %u - Suspended: %d\n", dwThreadId, CUtils::IsSuspendedThread(dwThreadId));

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;
	if (GetThreadContext(NtCurrentThread, &ctx))
	{
		auto bHasDebugRegister = (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr7);
		printf("\t* Context; Has debug register: %d Eip: %p Eax: %p\n", bHasDebugRegister, (void*)ctx.Eip, (void*)ctx.Eax);
	}

	MODULEINFO user32ModInfo = { 0 };
	if (GetModuleInformation(NtCurrentProcess, LoadLibraryA("user32"), &user32ModInfo, sizeof(user32ModInfo)))
	{
		DWORD dwUser32Low = (DWORD)user32ModInfo.lpBaseOfDll;
		DWORD dwUser32Hi = (DWORD)user32ModInfo.lpBaseOfDll + user32ModInfo.SizeOfImage;
		if (dwStartAddress >= dwUser32Low && dwStartAddress <= dwUser32Hi)
			printf("# WARNING # dwStartAddress in User32.dll\n");
	}

	if (dwStartAddress == (DWORD)LoadLibraryA)
		printf("# WARNING # dwStartAddress == LoadLibraryA\n");

	else if (dwStartAddress == (DWORD)LoadLibraryW)
		printf("# WARNING # dwStartAddress == LoadLibraryW\n");

	else if (dwStartAddress == (DWORD)LoadLibraryExA)
		printf("# WARNING # dwStartAddress == LoadLibraryExA\n");

	else if (dwStartAddress == (DWORD)LoadLibraryExW)
		printf("# WARNING # dwStartAddress == LoadLibraryExW\n");

	else if (dwStartAddress == (DWORD)GetProcAddress(LoadLibraryA("ntdll"), "RtlUserThreadStart"))
		printf("# WARNING # dwStartAddress == RtlUserThreadStart\n");

	else if (dwStartAddress == (DWORD)GetProcAddress(LoadLibraryA("ntdll"), "NtCreateThread"))
		printf("# WARNING # dwStartAddress == NtCreateThread\n");

	else if (dwStartAddress == (DWORD)GetProcAddress(LoadLibraryA("ntdll"), "NtCreateThreadEx"))
		printf("# WARNING # dwStartAddress == NtCreateThreadEx\n");

	else if (dwStartAddress == (DWORD)GetProcAddress(LoadLibraryA("ntdll"), "RtlCreateUserThread"))
		printf("# WARNING # dwStartAddress == RtlCreateUserThread\n");

	MEMORY_BASIC_INFORMATION mbi = { 0 };
	if (VirtualQuery((LPCVOID)dwStartAddress, &mbi, sizeof(mbi)))
	{
		if (mbi.Type != MEM_IMAGE)
			printf("# WARNING # mbi.Type != MEM_IMAGE\n");

		if (dwStartAddress == (DWORD)mbi.AllocationBase)
			printf("# WARNING # dwStartAddress == mbi.AllocationBase\n");
	}

	if (CUtils::IsLoadedAddress(dwStartAddress))
		printf("# WARNING # IsLoadedAddress(dwStartAddress)\n");

	if (CUtils::GetThreadOwnerProcessId(dwThreadId) != GetCurrentProcessId())
		printf("# WARNING # GetThreadOwnerProcessId(dwThreadId) != GetCurrentProcessId()\n");

	IMAGE_SECTION_HEADER * pCurrentSecHdr = (IMAGE_SECTION_HEADER*)dwStartAddress;
	if (pCurrentSecHdr)
	{
		BOOL IsMonitored =
			(pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_READ) &&
			(pCurrentSecHdr->Characteristics & IMAGE_SCN_CNT_CODE) && !(pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_DISCARDABLE);

		if (IsMonitored)
			printf("# WARNING # Remote code execution!\n");
	}

	return LdrInitializeThunk_(NormalContext, SystemArgument1, SystemArgument2);
}

void InitializeThreadCheck()
{
	auto hNtdll = LoadLibraryA("ntdll.dll");
	printf("hNtdll: %p\n", hNtdll);
	assert(hNtdll);

	auto LdrInitializeThunk_o = reinterpret_cast<LdrInitializeThunk>(GetProcAddress(hNtdll, "LdrInitializeThunk"));
	printf("LdrInitializeThunk: %p\n", LdrInitializeThunk_o);
	assert(LdrInitializeThunk_o);

	LdrInitializeThunk_ = reinterpret_cast<LdrInitializeThunk>(CUtils::DetourFunc(reinterpret_cast<PBYTE>(LdrInitializeThunk_o), reinterpret_cast<PBYTE>(LdrInitializeThunk_t), 5));
	printf("LdrInitializeThunk(detour): %p\n", LdrInitializeThunk_);

	DWORD dwOld = 0;
	auto bProtectRet = VirtualProtect(LdrInitializeThunk_, 5, PAGE_EXECUTE_READWRITE, &dwOld);
	assert(bProtectRet);
}

