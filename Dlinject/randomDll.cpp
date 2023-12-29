#include <Windows.h>


BOOL WINAPI DllMain(
    HINSTANCE hModule,  // handle to DLL module
    DWORD Reason,     // reason for calling function
    LPVOID lpvReserved)
{
	switch (Reason)
	{
	case DLL_PROCESS_ATTACH:
		MessageBoxW(NULL, L"Exposed!!! Gotcha!!!", L"What are you going to do about it?", MB_ICONEXCLAMATION | MB_OK);
		break;
	}

	return TRUE;
}