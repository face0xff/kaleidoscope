from mytea import encrypt_prog

import struct
import re
import sys
import os



OP = {
    "add": 0x80,
    "sub": 0x81,
    "mul": 0x82,
    "div": 0x83,
    "mod": 0x84,
    "cmp": 0x85,
    "and": 0x90,
    "or": 0x91,
    "xor": 0x92,
    "mov": 0xA0,
    "jmp": 0xB0,
    "jeq": 0xB1,
    "jne": 0xB2,
    "jgt": 0xB3,
    "jge": 0xB4,
    "jlt": 0xB5,
    "jle": 0xB6,
    "call": 0xC0,
    "ret": 0xC1,
    "push": 0xD0,
    "pop": 0xD1,
    "syscall": 0xE0,
}


REGS = {
    "r0": 0x0,
    "r1": 0x1,
    "r2": 0x2,
    "r3": 0x3,
    "r4": 0x4,
    "r5": 0x5,
    "r6": 0x6,
    "r7": 0x7,
    "r8": 0x8,
    "r9": 0x9,
    "ra": 0xA,
    "rb": 0xB,
    "fp": 0xC,
    "sp": 0xD,
    "lr": 0xE,
    "pc": 0xF,

    # the following two allow to exploit the oob reg mov leak bug
    "r(-1)": -0x1,
    "r(-2)": -0x2,
}



def parse_args(dst, src, data_labels):

    param = 0
    dst_ = 0
    src_ = 0
    additional = b""

    # Register
    if dst in REGS.keys():
        param |= 0b00 << 2
        dst_ = REGS[dst]
    
    # Memory
    elif dst[0] == "[" and (dst[-1] == "]" or dst[-2:] == "]b"):
        param |= 0b01 << 2
        if dst.endswith("]b"):
            dst = dst[1:-2]
            param |= 0b1 << 4
        else:
            dst = dst[1:-1]

        if dst in data_labels:
            addr = data_labels[dst][0]
        else:
            addr = int(dst, 0)

        if not (0 <= addr < 2**32):
            print("[x] Invalid destination address")
            exit(1)
        additional = addr.to_bytes(byteorder="little", length=4)
    
    else:
        print("[x] Invalid destination operand")
        exit(1)

    # Register
    if src in REGS.keys():
        param |= 0b00 << 0
        src_ = REGS[src]
    
    # Memory
    elif src[0] == "[" and (src[-1] == "]" or src[-2:] == "]b"):
        param |= 0b01 << 0
        if src.endswith("]b"):
            src = src[1:-2]
            param |= 0b1 << 4
        else:
            src = src[1:-1]

        if src in data_labels:
            addr = data_labels[src][0]
        else:
            addr = int(src, 0)

        if not (0 <= addr < 2**32):
            print("[x] Invalid source address")
            exit(1)
        additional = addr.to_bytes(byteorder="little", length=4)

    # Immediate
    else:
        param |= 0b10 << 0
        if src in data_labels or (src[0] == "$" and src[1:] in data_labels):
            if src[0] == "$":
                # asking for array length
                imm = len(data_labels[src[1:]][1])
            else:
                imm = data_labels[src][0]
        else:
            imm = int(src, 0)
        if imm < 0:
            print("[x] Negative integers are not supported")
            exit(1)
        if imm >= 2**32:
            print("[x] Immediate is too large (over 32 bits)")
            exit(1)
        if imm < 256:
            param |= 0b1 << 4
            src_ = imm
        else:
            additional = imm.to_bytes(byteorder="little", length=4)
            if (param >> 4) & 1:
                print("[x] Immediate does not fit in a byte")
                exit(1) 

    return param, dst_, src_, additional


def assemble(asm):

    program = b""
    program_data = b""

    labels = {}
    data_labels = {}


    # First pass to find all data variables and labels

    curr_pc = 0

    for line in asm.split("\n"):

        line = line.strip()

        if not line or line[0] in "#;/%":
            # empty or comment
            continue

        if line[-1] == ":":
            # label, store current address
            labels[line[:-1].lower()] = curr_pc
            continue
        
        if line[0] == ".":
            # data array, just append the string/bytes in program data
            # example syntax: .mystring b"\x01\x02\x03"
            data_name, data_value = line.split(" ", 1)
            data_name = data_name.lower()
            data_labels[data_name[1:]] = (len(program_data), eval(data_value))
            program_data += data_labels[data_name[1:]][1]
            continue

        line = line.lower()
        if " " in line:
            op, args = line.split(" ", 1)        
            args = re.split(r"[,\s]+", args)
        else:
            op = line
            args = None

        match op:

            case "add" | "sub" | "mul" | "div" | "mod" | "cmp" | "and" | "or" | "xor" | "mov":
                param, dst, src, additional = parse_args(args[0], args[1], data_labels)
                curr_pc += 4 + len(additional)

            case "jmp" | "jeq" | "jne" | "jgt" | "jge" | "jlt" | "jle" | "call":
                # consider jumps are ALWAYS relative otherwise we can't make a prediction :(
                curr_pc += 4

            case "ret" | "pop" | "syscall":
                curr_pc += 4

            case "push":
                src = args[0]
                src_ = 0
                param = 0
                additional = b""

                # Push register
                if src in REGS.keys():
                    param |= 0b00 << 0
                    src_ = REGS[src]

                # Push immediate
                else:
                    param |= 0b10 << 0
                    imm = int(src, 0)
                    if imm < 0:
                        print("[x] Negative integers are not supported")
                        exit(1)
                    if imm >= 2**32:
                        print("[x] Immediate is too large (over 32 bits)")
                        exit(1)
                    if imm < 256:
                        param |= 0b1 << 4
                        src_ = imm
                    else:
                        additional = imm.to_bytes(byteorder="little", length=4)

                curr_pc += 4 + len(additional)


    # Second pass to assemble the code

    for line in asm.split("\n"):

        line = line.strip().lower()

        if not line or line[0] in "#;/%":
            # empty or comment
            continue

        if " " in line:
            op, args = line.split(" ", 1)        
            args = re.split(r"[,\s]+", args)
        else:
            op = line
            args = None

        match op:

            case "add" | "sub" | "mul" | "div" | "mod" | "cmp" | "and" | "or" | "xor" | "mov":
                param, dst, src, additional = parse_args(args[0], args[1], data_labels)
                program += bytes([OP[op], param, dst % 256, src % 256]) + additional

            case "jmp" | "jeq" | "jne" | "jgt" | "jge" | "jlt" | "jle" | "call":
                if args[0] in labels:
                    # jump to a label
                    addr = labels[args[0]]
                    delta = addr - len(program)
                    if -0x8000 <= delta <= 0x7FFF:
                        # target is within reach -> relative jump
                        program += bytes([OP[op], 0x00])
                        program += struct.pack('>h', delta)
                    else:
                        # absolute jump
                        program += bytes([OP[op], 0x01, 0x00, 0x00])
                        program += addr.to_bytes(length=4, byteorder="little")
                else:
                    # absolute jump
                    addr = int(args[0], 0)
                    program += bytes([OP[op], 0x01, 0x00, 0x00])
                    program += addr.to_bytes(length=4, byteorder="little")

            case "ret":
                program += bytes([OP[op], 0x00, 0x00, 0x00])

            case "pop":
                if args[0] not in REGS:
                    print("Invalid pop target register")
                    exit(1)
                program += bytes([OP[op], 0x00, REGS[args[0]], 0x00])

            case "push":
                src = args[0]
                src_ = 0
                param = 0
                additional = b""

                # Push register
                if src in REGS.keys():
                    param |= 0b00 << 0
                    src_ = REGS[src]

                # Push immediate
                else:
                    param |= 0b10 << 0
                    imm = int(src, 0)
                    if imm < 0:
                        print("[x] Negative integers are not supported")
                        exit(1)
                    if imm >= 2**32:
                        print("[x] Immediate is too large (over 32 bits)")
                        exit(1)
                    if imm < 256:
                        param |= 0b1 << 4
                        src_ = imm
                    else:
                        additional = imm.to_bytes(byteorder="little", length=4)
                program += bytes([OP[op], param, 0x00, src_]) + additional

            case "syscall":
                syscall = int(args[0], 0)
                program += bytes([OP[op], syscall, 0x00, 0x00])

    return program, program_data



if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("[x] Usage: python assembler.py source.asm compiled.bin")
        exit(1)

    asm = open(sys.argv[1], "r").read()

    program, data = assemble(asm)
    assert len(program) % 4 == 0

    print("[+] Data:")
    print(f"[+] {data!r}")

    print("\n[+] Program:")
    for i in range(0, len(program), 4):
        print(f"[+] {program[i:i+4].hex().upper()}")

    key = os.urandom(16)

    body = b""
    body += key
    body += len(data).to_bytes(byteorder="little", length=4)
    body += data

    # Patch bytecode for exploit

    new_seed = 0x644e7750
    vm_syscallunimplemented_offset = 0x10C0
    tea_setseed_offset = 0x1F30
    program = program.replace(b"\x44\x33\x22\x11", struct.pack('<L', vm_syscallunimplemented_offset))
    program = program.replace(b"\x88\x77\x66\x55", struct.pack('<L', tea_setseed_offset))

    first_part, second_part = program.split(b"\xE0\x08\x00\x00")   # after syscall(8), seed changed to new_seed
    first_part += b"\xE0\x08\x00\x00"

    body += encrypt_prog(first_part, key, program_offset=len(data))  # default seed (0x0BAD1DEA)
    body += encrypt_prog(second_part, key, program_offset=len(data) + len(first_part), seed=new_seed)

    # print(body.hex())

    open(sys.argv[2], "wb").write(body)
