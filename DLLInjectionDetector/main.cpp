#include "main.h"
#pragma comment(lib, "psapi.lib")

int main()
{
	InitializeDLLCheck();
	InitializeThreadCheck();

	while (1)
		Sleep(10000); // keep alive

	return 0;
}