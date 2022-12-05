from z3 import *

hashlist = [
    0x739e80a2, 0x3aae80a3, 0x3ba4e79f, 0x78bac1f3,
    0x5ef9c1f3, 0x3bb9ec9f, 0x558683f4, 0x55fad594,
    0x6cbfdd9f
]

flag = [BitVec(f'flag_{i}', 32) for i in range(len(hashlist))]

s = Solver()
for hashvalue, block in zip(hashlist, flag):
    h = 0xacab3c0
    for i in range(4):
        h = RotateLeft(h ^ ((block >> (i*8)) & 0xff), 8)
    s.add(h == hashvalue)

r = s.check()
if r != sat:
    print(r)
    exit(1)

m = s.model()
s_flag = b""
for block in flag:
    s_flag += int.to_bytes(m[block].as_long(), 4, 'little')
print("SECCON{" + s_flag.decode() + "}")
