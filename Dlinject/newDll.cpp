#include <Windows.h>
#include <stdio.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)

int main(int argc, char* argv[]) {
	DWORD PID, TID = NULL;
	HANDLE hProcess, hThread = NULL;
	LPVOID rBuffer = NULL;
	HMODULE hKernel32 = NULL;
	wchar_t dllPath[MAX_PATH] = L"C:\\dev\\Dlinject\\x64\\debug\\Dlinject.dll";
	size_t pathSize = sizeof(dllPath);
	size_t bytesWritten = 0;

	if (argc < 2) {
		warn("usage: %s <PID>", argv[0]);
		return EXIT_FAILURE;
	}
	PID = atoi(argv[1]);
	info("trying to get a handle to %S", dllPath);
	hProcess = OpenProcess((PROCESS_VM_OPERATION | PROCESS_VM_WRITE), FALSE, PID);
	if (hProcess == NULL) {
		warn("Couldn't get handle to process (%ld), error: 0x%lx", PID, GetLastError());
		return EXIT_FAILURE;
	}
	okay("Got a handle to the process!");
	info("\\___[hProcess\n\t\\_0x%p]\n", hProcess);

	/*hKernel32 = LoadLibraryW(dllPath);

	if (hKernel32 == NULL) {
		warn("Couldn't get handle to subomi.dll, error: 0x%lx", GetLastError());
		return EXIT_FAILURE;
	}
	okay("Got a handle to subomi.dll!");
	info("---0x%p", hKernel32);

	info("Freeing the module");
	FreeLibrary(hKernel32);
	okay("Done! Press <enter> to exit");
	getchar();
	*/
	/* GETTING A HANDLE TO KERNEL32 */
	info("Getting Handle to Kernel32.dll");
	hKernel32 = GetModuleHandleW(L"kernel32");

	if (hKernel32 == NULL) {
		warn("Couldn't get handle to Kernel32.dll, error: 0x%lx", GetLastError());
		return EXIT_FAILURE;
	}
	okay("Got a handle to the process!");
	info("\\___[hKernel32\n\t\\_0x%p]\n", hKernel32);

	/*--- GETTING THE ADDRESS OF LOADLIBRARY ---*/
	info("Getting address of LoadLibraryW()");
	LPTHREAD_START_ROUTINE subomiLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
	okay("Got the address of LoadLibraryW()");
	info("\\___[LoadLibraryW\n\t\\_0x%p]\n", subomiLoadLibrary);

	/*---- ALLOCATING A BUFFER ----*/
	info("allocating memory in target process");
	rBuffer = VirtualAllocEx(hProcess, NULL, pathSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	if (rBuffer == NULL) {
		warn("Couldn't allocate a buffer to the target process memory, error: 0x%lx", GetLastError());
		goto CLEANUP;
	}
	okay("Allocated buffer in target process memory (PAGE_READWRITE)");

	/*---- WRITE TO MEMORY ----*/
	info("Writing to allocated buffer");
	WriteProcessMemory(hProcess, rBuffer, dllPath, pathSize, &bytesWritten);
	okay("Wrote %zu-bytes to the process memory", bytesWritten);
	
	/*---- CREATE A THREAD ----*/
	info("Creating a new thread");
	hThread = CreateRemoteThread(hProcess, NULL, 0, subomiLoadLibrary, rBuffer, 0, &TID);

	if (hThread == NULL) {
		warn("Unable to create thread, error: 0x%lx", GetLastError());
		goto CLEANUP;
	}
	okay("Created a new thread in the target process! (%ld)", TID);
	info("\\___[hThread\n\t\\_0x%p]\n", hThread);

	/* EXITING */
	info("Waiting for thread to finish");
	WaitForSingleObject(hThread, INFINITE);
	okay("Thread finished execution");
	goto CLEANUP;

CLEANUP: 
	if (hThread) {
		info("Closing handle to the thread");
		CloseHandle(hThread);
	}
	if (hProcess) {
		info("Closing handle to the process");
		CloseHandle(hProcess);
	}
	okay("Cleanup complete, see you next time");

	return EXIT_SUCCESS;
}