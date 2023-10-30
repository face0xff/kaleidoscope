#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "cryptoworker.h"
#include "vmworker.h"
#include "shared.h"
#include "tea.h"



int main(int argc, char *argv[]) {

	if (argc != 2) {
		printf("Usage: %s program.bin\n", argv[0]);
		return EXIT_FAILURE;
	}

    HANDLE fileHandle;
    DWORD bytesRead;

    HANDLE hCryptoWorkerThread = NULL;
    HANDLE hVMWorkerThread = NULL;

    BYTE* Program = NULL;

    DWORD EntryPoint;
    VMWORKER_PROGRAM_INFO ProgramInfo = { 0 };


    // Open program

    fileHandle = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        printf("Could not open file\n");
        return EXIT_FAILURE;
    }

    // Read TEA key (16-byte header)

    if (!ReadFile(fileHandle, Key, KEY_SIZE, &bytesRead, NULL) || (bytesRead != KEY_SIZE)) {
        CloseHandle(fileHandle);
        return EXIT_FAILURE;
    }

    // Read data section length (which gives the address of the entry point)
    if (!ReadFile(fileHandle, &EntryPoint, 4, &bytesRead, NULL) || (bytesRead != 4)) {
        CloseHandle(fileHandle);
        return EXIT_FAILURE;
    }

    // Read program

    Program = (BYTE*)malloc(MAX_PROGRAM_SIZE);
    if (!Program) {
        CloseHandle(fileHandle);
        return EXIT_FAILURE;
    }

    RtlZeroMemory(Program, MAX_PROGRAM_SIZE);

    if (!ReadFile(fileHandle, Program, MAX_PROGRAM_SIZE, &bytesRead, NULL) || (bytesRead == 0)) {
        CloseHandle(fileHandle);
        return EXIT_FAILURE;
    }

    CloseHandle(fileHandle);

    // Start crypto worker thread

    hCryptoWorkerThread = CreateThread(NULL, 0, CryptoWorkerMain, NULL, 0, &dwCryptoWorkerThreadId);
    if (!hCryptoWorkerThread) {
        printf("CreateThread failed (%lu)\n", GetLastError());
        return EXIT_FAILURE;
    }

    // Start VM worker thread

    ProgramInfo.Program = Program;
    ProgramInfo.EntryPoint = EntryPoint;

    hVMWorkerThread = CreateThread(NULL, 0, VMWorkerMain, &ProgramInfo, 0, &dwVMWorkerThreadId);
    if (!hVMWorkerThread) {
        printf("CreateThread failed (%lu)\n", GetLastError());
        return EXIT_FAILURE;
    }

    WaitForSingleObject(hVMWorkerThread, INFINITE);
    puts("Terminated");

	return EXIT_SUCCESS;

}
