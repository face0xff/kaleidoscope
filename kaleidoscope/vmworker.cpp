#include <windows.h>
#include <stdio.h>

#include "shared.h"
#include "emulator.h"


DWORD dwVMWorkerThreadId;


void SendDecryptInstructionRequest(DWORD EncryptedInstruction, DWORD ProgramCounter) {

	while (!PostThreadMessageA(dwCryptoWorkerThreadId, DECRYPT_INSTRUCTION_REQUEST, EncryptedInstruction, ProgramCounter)) {
		Sleep(100);
	}

}


DWORD ReceiveDecryptInstructionResponse() {

	MSG Msg;

	while (!PeekMessageA(&Msg, (HWND)-1, 0, 0, PM_REMOVE) || Msg.message != DECRYPT_INSTRUCTION_RESPONSE) {
		Sleep(10);
	}

	return (DWORD)Msg.wParam;

}


DWORD WINAPI VMWorkerMain(LPVOID lpParam) {
	
	VMContext VM;
	DWORD Instruction;
	
	VMWORKER_PROGRAM_INFO* ProgramInfo = (VMWORKER_PROGRAM_INFO*)lpParam;

	VM_Init(&VM, ProgramInfo->Program, ProgramInfo->EntryPoint);

	while (true) {

		if ((VM.Registers[PC] + 3) >= MAX_PROGRAM_SIZE)
			ExitProcess(EXIT_FAILURE);

		Instruction = VM_FetchInstruction(&VM);
		VM_HandleInstruction(&VM, Instruction);

	}

	return EXIT_SUCCESS;

}
