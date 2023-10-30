#include <windows.h>
#include <stdio.H>

#include "shared.h"
#include "tea.h"


BYTE Key[KEY_SIZE];
DWORD Seed;


__declspec(noinline) void TEA_SetSeed(volatile DWORD _unused, volatile DWORD NewSeed) {
	// unused arg allows to confuse the function with a syscall handler
	// this allows an attacker to call this function with a controlled arg
	Seed = NewSeed;
}


__declspec(noinline) DWORD TEA_EncryptWithSeedAndXor(DWORD x) {

	// Encrypts the couple (x, Seed) using TEA
	// Returns the XOR of the two 32-bit outputs

	DWORD v0 = x;
	DWORD v1 = Seed;

	DWORD delta = 0x9e3779b9;
	DWORD sum = 0;

	DWORD k0 = *(DWORD*)(Key + 4 * 0);
	DWORD k1 = *(DWORD*)(Key + 4 * 1);
	DWORD k2 = *(DWORD*)(Key + 4 * 2);
	DWORD k3 = *(DWORD*)(Key + 4 * 3);

	// DEBUG_PRINT("TEA_IN : v0=0x%08X, v1=0x%08X, k0=%08X, k1=%08X, k2=%08X, k3=%08X\n", v0, v1, k0, k1, k2, k3);

	for (char i = 0; i < 32; i++) {
		sum += delta;
		v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
		v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
	}

	// DEBUG_PRINT("TEA_OUT: v0=0x%08X, v1=0x%08X\n", v0, v1);

	return v0 ^ v1;

}
