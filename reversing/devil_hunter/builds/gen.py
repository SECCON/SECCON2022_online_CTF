FLAG = b"byT3c0d3_1nT3rpr3T3r_1s_4_L0T_0f_fun"
assert len(FLAG) == 36

ROTL = lambda a,b: ((a << b) | ((a) >> (32 - (b)))) & 0xffffffff

def myhash(v):
    h = 0xacab3c0
    for i in range(4):
        h = ROTL(h ^ ((v >> (i*8)) & 0xff), 8)
    return h

for i in range(0, len(FLAG), 4):
    v = myhash(int.from_bytes(FLAG[i:i+4], 'little'))
    print(f"  res &= (conv[{i//4}] == {v});")

with open("flag.txt", "wb") as f:
    f.write(b"SECCON{")
    f.write(FLAG)
    f.write(b"}")

print("[!] Alter source code region with the following line")
fake = b"not so easy :P\n"
line = "S"
for c in fake:
    line += chr(0x60 + (c & 0xf))
    line += chr(0x60 + ((c>>4) & 0xf))
print(line)
