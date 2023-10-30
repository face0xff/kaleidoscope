#pragma once
#include <windows.h>

// Remove in production
//#define DEBUG_MODE

#ifdef DEBUG_MODE
#define DEBUG_PRINT(...) do { fprintf( stderr, __VA_ARGS__ ); } while( false )
#else
#define DEBUG_PRINT(...) do { } while ( false )
#endif

#define MAX_PROGRAM_SIZE 0x10000


// Custom (private) messages for PostThreadMessage API.
// Can't go below 0x400 (WM_USER).
// Can't go over 0xFFFF either ("reserved by the system").
#define DECRYPT_INSTRUCTION_REQUEST   0x1337
#define DECRYPT_INSTRUCTION_RESPONSE  0x1338

extern DWORD dwCryptoWorkerThreadId;
extern DWORD dwVMWorkerThreadId;

typedef struct {
	DWORD EncryptedInstruction;
	DWORD ProgramCounter;
} DECRYPT_INSTRUCTION_REQUEST_MSG;

typedef struct {
	BYTE* Program;
	DWORD EntryPoint;
} VMWORKER_PROGRAM_INFO;
