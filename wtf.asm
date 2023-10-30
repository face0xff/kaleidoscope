; ----
; Data

.welcome  b"   __        __    _    __                         \n  / /_____ _/ /__ (_)__/ /__  __________  ___  ___ \n /  '_/ _ `/ / -_) / _  / _ \\(_-< __/ _ \\/ _ \\/ -_)\n/_/\\_\\\\_,_/_/\\__/_/\\_,_/\\___/___|__/\\___/ .__/\\__/ \n                                       /_/         \n\n"
.enterpassword  b"Enter the password: "
.good  b"Nice one!\n"
.nope  b"Uhh... no\n"

.flag0  b"\x00"
.flag1  b"\x00"
.flag2  b"\x00"
.flag3  b"\x00"
.flag4  b"\x00"
.flag5  b"\x00"
.flag6  b"\x00"
.flag7  b"\x00"
.flag8  b"\x00"
.flag9  b"\x00"
.flag10 b"\x00"
.flag11 b"\x00"
.flag12 b"\x00"
.flag13 b"\x00"
.flag14 b"\x00"
.flag15 b"\x00"
.flag16 b"\x00"
.flag17 b"\x00"
.flag18 b"\x00"
.flag19 b"\x00"
.flag20 b"\x00"
.flag21 b"\x00"
.flag22 b"\x00"
.flag23 b"\x00"
.flag24 b"\x00"
.flag25 b"\x00"
.flag26 b"\x00"
.flag27 b"\x00"
.flag28 b"\x00"
.flag29 b"\x00"
.flag30 b"\x00"
.flag31 b"\x00"


; ProhibitDynamicCode
.ProcessMitigationDynamicCodePolicy  b"\x01\x00\x00\x00" 

; MicrosoftSignedOnly
.ProcessMitigationBinarySignaturePolicy  b"\x01\x00\x00\x00"



jmp entrypoint

; ---------
; Functions

read_password:
mov R2, flag0
mov R3, 32
syscall 0  ; read
ret

leak_aslr_base:
; Leak VM_SyscallUnimplemented
mov R5, R(-2)
mov R6, R(-1)
sub R5, 0x11223344  ; to determine (dynamically patched later)
ret

anti_debug:
syscall 4  ; Leverage IsDebuggerPresent on host
cmp RA, 1
jne nodebug
syscall 2  ; exit
nodebug:
ret

anti_hook:
; Leverage SetProcessMitigationPolicy on host for ACG and CIG
mov R2, 2  ; ProcessDynamicCodePolicy
mov R3, ProcessMitigationDynamicCodePolicy  ; lpBuffer
mov R4, 4  ; dwLength
syscall 3
mov R2, 8  ; ProcessSignaturePolicy
mov R3, ProcessMitigationBinarySignaturePolicy  ; lpBuffer
mov R4, 4  ; dwLength
syscall 3
ret





; ----
; Code


entrypoint:

call anti_debug
call anti_hook

mov R2, welcome
mov R3, $welcome
syscall 1  ; write

mov R2, enterpassword
mov R3, $enterpassword
syscall 1  ; write

call read_password

call anti_debug

; Exploit <<<

call leak_aslr_base
mov R0, R5
mov R1, R6
add R0, 0x55667788  ; to determine (dynamically patched later)
mov R2, 0x644e7750  ; new seed
syscall 8  ; oob call [R0R1] -> call TEA_SetSeed with new seed

; At this point, the keystream changed!
; Need to re-encrypt all the next instructions with new seed

; Simple flag verification with CRT pairs...

mov RA, 0

mov R8, [flag0]
mov R9, R8
mod R8, 76335
mod R9, 120026
xor R8, 27241
xor R9, 68181
or RA, R8
or RA, R9

mov R8, [flag4]
mov R9, R8
mod R8, 110125
mod R9, 108506
xor R8, 92563
xor R9, 45127
or RA, R8
or RA, R9

mov R8, [flag8]
mov R9, R8
mod R8, 98851
mod R9, 115966
xor R8, 42287
xor R9, 46766
or RA, R8
or RA, R9

mov R8, [flag12]
mov R9, R8
mod R8, 98564
mod R9, 114611
xor R8, 96512
xor R9, 58270
or RA, R8
or RA, R9

cmp RA, 0
jne fail

mov R8, [flag16]
mov R9, R8
mod R8, 69129
mod R9, 88694
xor R8, 14900
xor R9, 82705
or RA, R8
or RA, R9

mov R8, [flag20]
mov R9, R8
mod R8, 109460
mod R9, 68883
xor R8, 24419
xor R9, 41368
or RA, R8
or RA, R9

mov R8, [flag24]
mov R9, R8
mod R8, 82595
mod R9, 65709
xor R8, 40736
xor R9, 58761
or RA, R8
or RA, R9

mov R8, [flag28]
mov R9, R8
mod R8, 130942
mod R9, 71079
xor R8, 22132
xor R9, 26140
or RA, R8
or RA, R9

cmp RA, 0
jne fail

mov R2, good
mov R3, $good
syscall 1  ; write
syscall 2  ; exit

fail:
mov R2, nope
mov R3, $nope
syscall 1  ; write
syscall 2  ; exit
