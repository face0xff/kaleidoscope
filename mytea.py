def tea_encrypt(y, z, key):

    s = 0
    delta = 0x9e3779b9

    k0 = int.from_bytes(key[:4], byteorder="little")
    k1 = int.from_bytes(key[4:8], byteorder="little")
    k2 = int.from_bytes(key[8:12], byteorder="little")
    k3 = int.from_bytes(key[12:16], byteorder="little")

    for _k in range(32):
        s = (s + delta) & 0xFFFFFFFF
        y = (y + (((z << 4) + k0) ^ (z + s) ^ ((z >> 5) + k1))) & 0xFFFFFFFF
        z = (z + (((y << 4) + k2) ^ (y + s) ^ ((y >> 5) + k3))) & 0xFFFFFFFF

    return y, z


def encrypt_prog(program, key, program_offset=0, seed=0x0BAD1DEA):

    encrypted = b""

    for i in range(0, len(program), 4):
        c1, c2 = tea_encrypt(program_offset + i, seed, key)
        c = c1 ^ c2
        z = int.from_bytes(program[i:i + 4], byteorder="little") ^ c
        encrypted += z.to_bytes(length=4, byteorder="little")

    return encrypted
