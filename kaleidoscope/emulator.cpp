#include <windows.h>
#include <stdio.h>

#include "shared.h"
#include "emulator.h"
#include "vmworker.h"


using SetProcessMitigationPolicyFunction = decltype(&SetProcessMitigationPolicy);
using IsDebuggerPresentFunction = decltype(&IsDebuggerPresent);

HMODULE Kernel32;


/* Syscalls */

DWORD VM_SyscallUnimplemented(VMContext* VM, DWORD _R2, DWORD _R3, DWORD _R4, DWORD _R5) {
	return 0x0;
}


DWORD VM_SyscallRead(VMContext* VM, DWORD BufferOffset, DWORD Size, DWORD _R4, DWORD _R5) {
	return (DWORD)fread(VM->Program + BufferOffset, 1, Size, stdin);
}


DWORD VM_SyscallWrite(VMContext* VM, DWORD BufferOffset, DWORD Size, DWORD _R4, DWORD _R5) {
	return (DWORD)fwrite(VM->Program + BufferOffset, 1, Size, stdout);
}


DWORD VM_SyscallExit(VMContext* VM, DWORD _R2, DWORD _R3, DWORD _R4, DWORD _R5) {
	free(VM->Stack);
	ExitThread(EXIT_SUCCESS);
	return 0x0;
}

DWORD VM_SyscallSetProcessMitigationPolicy(VMContext* VM, DWORD MitigationPolicy, DWORD BufferOffset, DWORD Length, DWORD _R5) {
	DWORD ProcName[7] = { 0x5bd9a58d, 0x6eceafac, 0x62e0b3ad, 0x6acaa9aa, 0x65c2a9aa, 0x62c1af8e, 0xbadb9bd };
	for (int i = 0; i < sizeof(ProcName) / sizeof(ProcName[0]); i++)
		ProcName[i] ^= 0x0badc0de;
	SetProcessMitigationPolicyFunction SetProcessMitigationPolicyFunc = (SetProcessMitigationPolicyFunction)GetProcAddress(Kernel32, (LPCSTR)ProcName);
	return SetProcessMitigationPolicyFunc((PROCESS_MITIGATION_POLICY)MitigationPolicy, VM->Program + BufferOffset, Length);
}

DWORD VM_SyscallIsDebuggerPresent(VMContext* VM, DWORD _R2, DWORD _R3, DWORD _R4, DWORD _R5) {
	DWORD ProcName[7] = { 0x6ee9b397, 0x6ccab5bc, 0x79fdb2bb, 0x65c8b3bb, 0xbadc0aa };
	for (int i = 0; i < sizeof(ProcName) / sizeof(ProcName[0]); i++)
		ProcName[i] ^= 0x0badc0de;
	IsDebuggerPresentFunction IsDebuggerPresentFunc = (IsDebuggerPresentFunction)GetProcAddress(Kernel32, (LPCSTR)ProcName);
	return IsDebuggerPresentFunc() != 0;
}


/* Fetcher */

DWORD VM_FetchInstruction(VMContext* VM) {
	
	DWORD ProgramCounter = VM->Registers[PC];
	DWORD EncryptedInstruction;
	DWORD DecryptedInstruction;

	if (ProgramCounter >= MAX_PROGRAM_SIZE) {
		puts("Program overflow");
		ExitProcess(EXIT_FAILURE);
	}

	EncryptedInstruction = *(DWORD*)&VM->Program[ProgramCounter];
	DEBUG_PRINT("[%08X] Fetched encrypted instruction: %08X\n", VM->Registers[PC], EncryptedInstruction);

	SendDecryptInstructionRequest(EncryptedInstruction, ProgramCounter);

	DecryptedInstruction = ReceiveDecryptInstructionResponse();
	DEBUG_PRINT("[%08X] Decrypted instruction: %08X\n", VM->Registers[PC], DecryptedInstruction);

	return DecryptedInstruction;
}


/* Helpers */

DWORD VM_LoadSrcOrDst(VMContext* VM, CHAR SrcOrDst, UCHAR Type, UCHAR IsByte) {

	DWORD Addr;

	switch (Type) {

	// Register
	case 0:
		if (SrcOrDst < N_REGISTERS) {
			// VULNERABILITY 2 (LEAK) ---
			// We do check for the upper bound, BUT there's an issue
			// SrcOrDst is signed, so we can underflow to the SyscallHandlers array ;)
			// This allows to leak function pointers and break ASLR
			return VM->Registers[SrcOrDst];
		}
		ExitProcess(EXIT_FAILURE);

	// Memory
	case 1:
		VM->Registers[PC] += 4;
		Addr = VM_FetchInstruction(VM);
		if (IsByte && (Addr < MAX_PROGRAM_SIZE)) {
			return (DWORD)(*(BYTE*)&VM->Program[Addr]);
		}
		if (!IsByte && ((Addr + 3) < MAX_PROGRAM_SIZE)) {
			return *(DWORD*)&VM->Program[Addr];
		}
		ExitProcess(EXIT_FAILURE);

	// Immediate
	case 2:
		if (IsByte) {
			return ((DWORD)(UCHAR)SrcOrDst);
		}
		else {
			VM->Registers[PC] += 4;
			return VM_FetchInstruction(VM);
		}

	default:
		ExitProcess(EXIT_FAILURE);

	}

}


void VM_StoreDst(VMContext* VM, UCHAR Dst, UCHAR Param, DWORD Value) {

	DWORD Addr;

	UCHAR Type = (Param >> 2) & 3;
	UCHAR IsByte = (Param >> 4) & 1;

	switch (Type) {

	// Register
	case 0:
		if (Dst < N_REGISTERS) {
			// This time around, Dst is unsigned, so no direct write primitive
			VM->Registers[Dst] = Value;
		}
		else {
			ExitProcess(EXIT_FAILURE);
		}
		break;

	// Memory
	case 1:
		VM->Registers[PC] += 4;
		Addr = VM_FetchInstruction(VM);
		if (IsByte && (Addr < MAX_PROGRAM_SIZE)) {
			*(BYTE*)&VM->Program[Addr] = Value & 0xFF;
		}
		else if (!IsByte && ((Addr + 3) < MAX_PROGRAM_SIZE)) {
			*(DWORD*)&VM->Program[Addr] = Value;
		}
		else {
			ExitProcess(EXIT_FAILURE);
		}
		break;

	default:
		ExitProcess(EXIT_FAILURE);

	}

}


void VM_GetArgs(VMContext* VM, VMInstArgs* Args, UCHAR Src, UCHAR Dst, UCHAR Param) {

	Args->X = VM_LoadSrcOrDst(VM, Src, Param & 3, (Param >> 4) & 1);
	Args->Y = VM_LoadSrcOrDst(VM, Dst, (Param >> 2) & 3, (Param >> 4) & 1);

}


DWORD VM_GetJumpAddr(VMContext* VM, UCHAR Param, UCHAR Src, UCHAR Dst) {

	SHORT RelativeOffset;
	DWORD Addr;

	if (Param & 1) {
		// Absolute jump
		VM->Registers[PC] += 4;
		Addr = VM_FetchInstruction(VM);
	}

	else {
		// Relative jump
		RelativeOffset = Src | (Dst << 8);
		Addr = VM->Registers[PC] + RelativeOffset;
	}

	if ((Addr + 3) < MAX_PROGRAM_SIZE)
		return Addr;

	ExitProcess(EXIT_FAILURE);

}


/* Instruction handler */

void VM_HandleInstruction(VMContext* VM, DWORD Instruction) {
	
	UCHAR Src = (Instruction >> 24) & 0xFF;
	UCHAR Dst = (Instruction >> 16) & 0xFF;
	UCHAR Param = (Instruction >> 8) & 0xFF;
	UCHAR Opcode = Instruction & 0xFF;

	VMInstArgs Args;

	switch (Opcode) {

	case OP_ADD:
		VM_GetArgs(VM, &Args, Src, Dst, Param);
		VM_StoreDst(VM, Dst, Param, (Args.X + Args.Y));
		VM->Registers[PC] += 4;
		break;

	case OP_SUB:
		VM_GetArgs(VM, &Args, Src, Dst, Param);
		VM_StoreDst(VM, Dst, Param, (Args.Y - Args.X));
		VM->Registers[PC] += 4;
		break;

	case OP_MUL:
		VM_GetArgs(VM, &Args, Src, Dst, Param);
		VM_StoreDst(VM, Dst, Param, (Args.X * Args.Y));
		VM->Registers[PC] += 4;
		break;

	case OP_DIV:
		VM_GetArgs(VM, &Args, Src, Dst, Param);
		if (Args.X == 0)
			ExitProcess(EXIT_FAILURE);
		VM_StoreDst(VM, Dst, Param, (Args.Y / Args.X));
		VM->Registers[PC] += 4;
		break;

	case OP_MOD:
		VM_GetArgs(VM, &Args, Src, Dst, Param);
		if (Args.X == 0)
			ExitProcess(EXIT_FAILURE);
		VM_StoreDst(VM, Dst, Param, (Args.Y % Args.X));
		VM->Registers[PC] += 4;
		break;

	case OP_CMP:
		VM_GetArgs(VM, &Args, Src, Dst, Param);
		if (Args.X == Args.Y) VM->Flag |= VM_FLAG_EQUAL;
		else VM->Flag &= ~VM_FLAG_EQUAL;
		if (Args.X > Args.Y) VM->Flag |= VM_FLAG_GREATER;
		else VM->Flag &= ~VM_FLAG_GREATER;
		VM->Registers[PC] += 4;
		break;

	case OP_AND:
		VM_GetArgs(VM, &Args, Src, Dst, Param);
		VM_StoreDst(VM, Dst, Param, (Args.X & Args.Y));
		VM->Registers[PC] += 4;
		break;

	case OP_OR:
		VM_GetArgs(VM, &Args, Src, Dst, Param);
		VM_StoreDst(VM, Dst, Param, (Args.X | Args.Y));
		VM->Registers[PC] += 4;
		break;

	case OP_XOR:
		VM_GetArgs(VM, &Args, Src, Dst, Param);
		VM_StoreDst(VM, Dst, Param, (Args.X ^ Args.Y));
		VM->Registers[PC] += 4;
		break;

	case OP_MOV:
		VM_StoreDst(VM, Dst, Param, VM_LoadSrcOrDst(VM, Src, Param & 3, (Param >> 4) & 1));
		VM->Registers[PC] += 4;
		break;

	case OP_JMP:
		VM->Registers[PC] = VM_GetJumpAddr(VM, Param, Src, Dst);
		break;

	case OP_JEQ:
		if (VM->Flag & VM_FLAG_EQUAL)
			VM->Registers[PC] = VM_GetJumpAddr(VM, Param, Src, Dst);
		else
			VM->Registers[PC] += 4;
		break;

	case OP_JNE:
		if (!(VM->Flag & VM_FLAG_EQUAL))
			VM->Registers[PC] = VM_GetJumpAddr(VM, Param, Src, Dst);
		else
			VM->Registers[PC] += 4;
		break;

	case OP_JGT:
		if (VM->Flag & VM_FLAG_GREATER)
			VM->Registers[PC] = VM_GetJumpAddr(VM, Param, Src, Dst);
		else
			VM->Registers[PC] += 4;
		break;

	case OP_JGE:
		if ((VM->Flag & VM_FLAG_GREATER) | (VM->Flag & VM_FLAG_EQUAL))
			VM->Registers[PC] = VM_GetJumpAddr(VM, Param, Src, Dst);
		else
			VM->Registers[PC] += 4;
		break;

	case OP_JLT:
		if (!((VM->Flag & VM_FLAG_GREATER) | (VM->Flag & VM_FLAG_EQUAL)))
			VM->Registers[PC] = VM_GetJumpAddr(VM, Param, Src, Dst);
		else
			VM->Registers[PC] += 4;
		break;

	case OP_JLE:
		if (!(VM->Flag & VM_FLAG_GREATER))
			VM->Registers[PC] = VM_GetJumpAddr(VM, Param, Src, Dst);
		else
			VM->Registers[PC] += 4;
		break;

	case OP_CALL:
		if ((VM->Registers[SP] == 0) || (VM->Registers[SP] > STACK_SIZE))
			ExitProcess(EXIT_FAILURE);
		VM->Stack[--VM->Registers[SP]] = VM->Registers[PC] + 4;
		VM->Registers[PC] = VM_GetJumpAddr(VM, Param, Src, Dst);
		break;

	case OP_RET:
		if (VM->Registers[SP] >= STACK_SIZE)
			ExitProcess(EXIT_FAILURE);
		VM->Registers[PC] = VM->Stack[VM->Registers[SP]];
		VM->Registers[SP]++;
		break;

	case OP_PUSH:
		if ((VM->Registers[SP] == 0) || (VM->Registers[SP] > STACK_SIZE))
			ExitProcess(EXIT_FAILURE);
		VM->Stack[--VM->Registers[SP]] = VM_LoadSrcOrDst(VM, Src, Param & 3, (Param >> 4) & 1);
		VM->Registers[PC] += 4;
		break;

	case OP_POP:
		if (VM->Registers[SP] >= STACK_SIZE)
			ExitProcess(EXIT_FAILURE);
		VM_StoreDst(VM, Dst, Param, VM->Stack[VM->Registers[SP]]);
		VM->Registers[SP]++;
		VM->Registers[PC] += 4;
		break;

	case OP_SYSCALL:
		// VULNERABILITY 1 (ARBITRARY CALL) ---
		// There's an off-by-one in the following comparison.
		// This allows to call an arbitrary pointer formed by the registers R0 and R1,
		// because registers sit right after the syscall handler table in the VM context
		if (Param > N_SYSCALLS)
			ExitProcess(EXIT_FAILURE);
		VM->Registers[RA] = VM->SyscallHandlers[Param](
			VM,
			VM->Registers[R2],
			VM->Registers[R3],
			VM->Registers[R4],
			VM->Registers[R5]
		);
		VM->Registers[PC] += 4;
		break;

	default:
		ExitProcess(EXIT_FAILURE);

	}

}


void VM_Init(VMContext* VM, BYTE* Program, DWORD EntryPoint) {

	RtlZeroMemory(VM, sizeof(VMContext));

	VM->Program = Program;

	for (int k = 0; k < N_SYSCALLS; k++) {
		VM->SyscallHandlers[k] = VM_SyscallUnimplemented;
	}

	VM->SyscallHandlers[SYSCALL_READ] = VM_SyscallRead;
	VM->SyscallHandlers[SYSCALL_WRITE] = VM_SyscallWrite;
	VM->SyscallHandlers[SYSCALL_EXIT] = VM_SyscallExit;
	VM->SyscallHandlers[SYSCALL_SETPROCESSMITIGATIONPOLICY] = VM_SyscallSetProcessMitigationPolicy;
	VM->SyscallHandlers[SYSCALL_ISDEBUGGERPRESENT] = VM_SyscallIsDebuggerPresent;

	VM->Stack = (DWORD*)calloc(STACK_SIZE, sizeof(DWORD));
	if (!VM->Stack)
		ExitProcess(EXIT_FAILURE);

	VM->Registers[PC] = EntryPoint;
	VM->Registers[SP] = STACK_SIZE;

	Kernel32 = LoadLibraryA("kernel32.dll");

}

