#include <windows.h>
#include <stdio.h>

#include "shared.h"
#include "tea.h"


DWORD dwCryptoWorkerThreadId;


void SendDecryptInstructionResponse(DWORD DecryptedInstruction) {

	while (!PostThreadMessageA(dwVMWorkerThreadId, DECRYPT_INSTRUCTION_RESPONSE, DecryptedInstruction, 0)) {
		Sleep(10);
	}

}


void ReceiveDecryptInstructionRequest(DECRYPT_INSTRUCTION_REQUEST_MSG * Req) {

	MSG Msg;

	while (!PeekMessageA(&Msg, (HWND)-1, 0, 0, PM_REMOVE) || Msg.message != DECRYPT_INSTRUCTION_REQUEST) {
		Sleep(10);
	}
	
	Req->EncryptedInstruction = (DWORD)Msg.wParam;
	Req->ProgramCounter = (DWORD)Msg.lParam;

}


DWORD WINAPI CryptoWorkerMain(LPVOID lpParam) {
	
	DWORD DecryptedInstruction;
	DECRYPT_INSTRUCTION_REQUEST_MSG Req;

	// Set constant seed
	// Declare as volatile so that the compiler doesn't try to optimize it away
	volatile DWORD seed = 0x0BAD1DEA;
	TEA_SetSeed(0, seed);

	while (true) {

		ReceiveDecryptInstructionRequest(&Req);
		DecryptedInstruction = Req.EncryptedInstruction ^ TEA_EncryptWithSeedAndXor(Req.ProgramCounter);

		SendDecryptInstructionResponse(DecryptedInstruction);

	}

	return EXIT_SUCCESS;

}
