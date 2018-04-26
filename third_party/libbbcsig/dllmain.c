#ifdef _WIN32
#include <windows.h>

/**
 * 
 */
BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,
	DWORD dwReason,
	LPVOID lpReserved
) {

	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	default:
		break;
	}

	return TRUE;
}

#endif
