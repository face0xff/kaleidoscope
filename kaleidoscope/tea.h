#pragma once
#include <windows.h>

#define KEY_SIZE 0x10

extern BYTE Key[KEY_SIZE];
extern DWORD Seed;

void TEA_SetSeed(DWORD _unused, DWORD NewSeed);
DWORD TEA_EncryptWithSeedAndXor(DWORD x);
