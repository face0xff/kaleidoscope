#pragma once
#include <windows.h>
#include <stdint.h>


#define N_SYSCALLS   0x8
#define N_REGISTERS  0x10
#define STACK_SIZE   0x2000



/* Registers */

#define R0  0x0
#define R1  0x1
#define R2  0x2
#define R3  0x3
#define R4  0x4
#define R5  0x5
#define R6  0x6
#define R7  0x7
#define R8  0x8
#define R9  0x9
#define RA  0xA
#define RB  0xB
#define FP  0xC
#define SP  0xD
#define LR  0xE
#define PC  0xF


/* Syscalls */

#define SYSCALL_READ                        0x0
#define SYSCALL_WRITE                       0x1
#define SYSCALL_EXIT                        0x2
#define SYSCALL_SETPROCESSMITIGATIONPOLICY  0x3
#define SYSCALL_ISDEBUGGERPRESENT           0x4


/* Comparison flags */

#define VM_FLAG_EQUAL    0x1
#define VM_FLAG_GREATER  0x2


/* List of opcodes */

// Arithmetic
#define OP_ADD  0x80
#define OP_SUB  0x81
#define OP_MUL  0x82
#define OP_DIV  0x83
#define OP_MOD  0x84
#define OP_CMP  0x85

// Logic
#define OP_AND  0x90
#define OP_OR   0x91
#define OP_XOR  0x92

// Movement
#define OP_MOV  0xA0

// Branching
#define OP_JMP  0xB0
#define OP_JEQ  0xB1
#define OP_JNE  0xB2
#define OP_JGT  0xB3
#define OP_JGE  0xB4
#define OP_JLT  0xB5
#define OP_JLE  0xB6

// Calling
#define OP_CALL 0xC0
#define OP_RET  0xC1

// Stack
#define OP_PUSH 0xD0
#define OP_POP  0xD1

// Misc
#define OP_SYSCALL  0xE0

/* End of opcodes */


struct VMContext;

typedef DWORD VM_SYSCALL_FN(struct VMContext*, DWORD, DWORD, DWORD, DWORD);

typedef struct VMContext {

	BYTE* Program;
	VM_SYSCALL_FN* SyscallHandlers[N_SYSCALLS];
	DWORD Registers[N_REGISTERS];
	UCHAR Flag;
	DWORD* Stack;

} VMContext;

typedef struct {
	DWORD X;
	DWORD Y;
} VMInstArgs;


void VM_Init(VMContext* VM, BYTE* Program, DWORD EntryPoint);
DWORD VM_FetchInstruction(VMContext* VM);
void VM_HandleInstruction(VMContext* VM, DWORD Instruction);
