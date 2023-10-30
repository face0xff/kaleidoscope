#pragma once
#include <windows.h>

void SendDecryptInstructionRequest(DWORD EncryptedInstruction, DWORD ProgramCounter);
DWORD ReceiveDecryptInstructionResponse();
DWORD WINAPI VMWorkerMain(LPVOID lpParam);
