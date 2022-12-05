from z3 import *

aa = 0x8b228b98e458
bb = 0x5a7b12
cc = 0x8d072f
dd = 0xf9bf1370

s = Solver()

a = BitVec('a', 64)
b = BitVec('b', 64)
c = BitVec('c', 64)
d = BitVec('d', 64)
s.add(0 < b, b < 0x1000000)
s.add(0 < c, c < 0x1000000)
s.add(0 < d, d < 0x100000000)
s.add(a + b == aa + bb)
s.add(b + c == bb + cc)
s.add(c + d == cc + dd)
s.add(d + a == dd + aa)
s.add(b ^ c ^ d == bb ^ cc ^ dd)

while True:
    r = s.check()
    if r == sat:
        m = s.model()
        print(f"SECCON{{{m[a].as_long():012x}-{m[b].as_long():06x}-{m[c].as_long():06x}-{m[d].as_long():08x}}}")
        s.add(a != m[a].as_long())
    else:
        print("None!")
        break
