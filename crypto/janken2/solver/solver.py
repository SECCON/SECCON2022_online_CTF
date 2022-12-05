import os
import random
from ptrlib import Socket
from z3 import Solver, BitVec, BitVecVal, sat, LShR, simplify, If


class MersenneTwister():
    N = 624
    M = 397
    A = [0, 0x9908b0df]
    UPPER_MASK = 0x80000000
    LOWER_MASK = 0x7fffffff

    def __init__(self):
        self.solver = Solver()
        self.state = [BitVec(f"state_{i}", 32) for i in range(self.N)]
        self.initial_state = self.state[:]
        self.p = 0

    def next_value(self) -> int:
        p, q = self.p, (self.p + 1) % self.N
        # update state
        a = self.state[p] & self.UPPER_MASK
        b = self.state[q] & self.LOWER_MASK
        x = a | b

        k = (p + self.M) % self.N
        return simplify(
            If(x & 1 == 0,
               self.A[0] ^ self.state[k] ^ LShR(x, 1),
               self.A[1] ^ self.state[k] ^ LShR(x, 1),
               )
        )

    def next(self):
        y = self.next_value()
        self.state[self.p] = y
        self.p = (self.p + 1) % self.N
        return self._tempering(y)

    def _tempering(self, y):
        y ^= LShR(y, 11)
        y ^= (y << 7) & 0x9d2c5680
        y ^= (y << 15) & 0xefc60000
        y ^= LShR(y, 18)
        return simplify(y)

    def solve_state(self):
        assert mt.solver.check() == sat
        m = mt.solver.model()
        return [m[k].as_long() for k in self.initial_state]


N = 624


def init_genrand(s):
    state = [0 for _ in range(N)]
    state[0] = s
    for i in range(1, N):
        state[i] = (1812433253 * (state[i-1] ^
                    (state[i-1] >> 30)) + i) & 0xffffffff
    return state


def init_by_array(init_key):
    state = init_genrand(19650218)

    key_len = len(init_key)
    k = N if N > key_len else key_len
    i, j = 1, 0
    while k != 0:
        state[i] = ((state[i] ^ ((state[i-1] ^ (state[i-1] >> 30))
                    * 1664525)) + init_key[j] + j) & 0xffffffff

        i += 1
        j += 1

        if i >= N:
            state[0] = state[N-1]
            i = 1
        if j >= key_len:
            j = 0
        k -= 1

    for k in range(N-1):
        state[i] = (
            (state[i] ^ ((state[i-1] ^ (state[i-1] >> 30)) * 1566083941)) - i) & 0xffffffff
        i += 1
        if i >= N:
            state[0] = state[N-1]
            i = 1
    state[0] = 0x80000000
    return state


def solve_init_by_array(desired_state):
    assert desired_state[0] == 0x80000000

    # forward
    init_key = [BitVec(f"init_key_{i}", 32) for i in range(N)]
    init_key_decls = init_key[:]
    state = init_genrand(19650218)
    for i in range(len(state)):
        state[i] = BitVecVal(state[i], 32)

    i, j = 1, 0
    key_len = N
    for k in range(max(N, key_len)):
        state[i] = simplify(
            (state[i] ^ ((state[i-1] ^ LShR(state[i-1], 30)) * 1664525)) + init_key[j] + j)
        i += 1
        j += 1
        if i >= N:
            state[0] = state[N-1]
            i = 1
        if j >= key_len:
            j = 0
    middle_state = state[:]

    # backward
    state = [BitVec(f"state{i}", 32) for i in range(N)]
    state_decls = state[:]
    for k in range(N-1):
        state[i] = simplify(
            (state[i] ^ ((state[i-1] ^ LShR(state[i-1], 30)) * 1566083941)) - i)
        i += 1
        if i >= N:
            state[0] = state[N-1]
            i = 1
    state[0] = 0x80000000

    solver = Solver()
    for t in range(N):
        solver.add(state[t] == desired_state[t])
    assert solver.check() == sat
    m = solver.model()
    middle_values = [m[k].as_long() for k in state_decls[1:]]

    solver = Solver()
    # for k in init_key_decls:
    #     for s in range(4):
    #         e = Extract((s+1)*8-1, s*8, k)
    #         solver.add(e != 0x0a)
    #         solver.add(e < 128)

    for t in range(N-1):
        # state[0] is not in the middle_values
        solver.add(middle_state[t+1] == middle_values[t])
    assert solver.check() == sat
    m = solver.model()
    return [m[k].as_long() for k in init_key_decls]


def unseed(init_keys):
    bs = b"".join(k.to_bytes(4, "little") for k in init_keys)
    return int.from_bytes(bs, "little")


sock = Socket(os.getenv("SECCON_HOST"), int(os.getenv("SECCON_PORT")))
witch_spell = int(sock.recvregex(r"My spell is ([0-9a-fA-F]+)")[0], 16)


# find seed
witch_random = random.Random()
witch_random.seed(witch_spell)

mt = MersenneTwister()
for i in range(666):
    witch_hand = witch_random.randint(0, 2)
    desired_hand = (witch_hand - 2) % 3
    v = mt.next()
    mt.solver.add(LShR(v, 30) == desired_hand)
desired_state = mt.solve_state()

init_key = solve_init_by_array(desired_state)
seed = unseed(init_key)

# check
witch_random.seed(witch_spell)
my_random = random.Random()
my_random.seed(seed)


def janken(a, b):
    return (a - b + 3) % 3


for _ in range(666):
    yoshi_hand = witch_random.randint(0, 2)
    my_hand = my_random.randint(0, 2)

    assert janken(my_hand, yoshi_hand) == 1

sock.sendlineafter("your spell: ", hex(seed))
print(sock.recvline())
print(sock.recvline())
print(seed)
