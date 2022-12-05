from Crypto.Util.number import long_to_bytes
from pwn import remote
from util import int_nth_root, crt, mod_sqrt

import os


def create_conn():
    host = os.getenv('SECCON_HOST')
    port = os.getenv('SECCON_PORT')
    return remote(host, port)


def calc_b(a, p, fixed_point):
    for k in range(1,12):
        b = k * p - fixed_point * (a-1) - fixed_point**2
        if b < 0:
            continue

        return b


# x^2 + ax + b = 0 mod p
def solve_quadratic_equation(a: int,b: int,p: int):
    rhs = (a**2 * pow(4, -1, p) - b) % p
    if pow(rhs, (p-1)//2, p) == -1:
        return []

    ret = []
    _xs = mod_sqrt(rhs, p)
    for _x in _xs:
        x = (_x - a * pow(2, -1, p)) % p
        ret.append(x)

    return ret


def search_seeds(a,b,p,fixed_point):
    ret = []
    qcg = lambda x: (x**2 + a*x + b) % p
    # x^2 + ax + b = fixed_point mod p
    # of cource, one of solutions is fixed_point
    sol = solve_quadratic_equation(a,b-fixed_point,p)
    for x in sol:
        assert qcg(x) == fixed_point
        ret.append(x)
        if x != fixed_point:
            _sol = solve_quadratic_equation(a,b-x,p)

    for x in _sol:
        assert qcg(qcg(x)) == fixed_point
        ret.append(x)
        __sol = solve_quadratic_equation(a,b-x,p)
        for _x in __sol:
            assert qcg(qcg(qcg(_x))) == fixed_point
            ret.append(_x)

    return ret


def exploit():
    fixed_point = 11
    sc = create_conn()
    sc.recvuntil(b"a=")
    a = int(sc.recvline())
    sc.recvuntil(b"p=")
    p = int(sc.recvline())
    b = calc_b(a,p,fixed_point)
    rng = lambda x: (x**2 + a*x + b) % p
    assert rng(fixed_point) == fixed_point

    seeds = search_seeds(a,b,p,fixed_point)

    # unlucky
    if len(seeds) < 5:
        return None

    sc.recvuntil(b"[b]ackdoor!!: ")
    sc.sendline(str(b).encode())

    for i in range(5):
        sc.recvuntil(b"seed: ")
        sc.sendline(str(seeds[i]).encode())

    problem = []
    for i in range(5):
        sc.recvuntil(b"n=")
        n = int(sc.recvline())
        sc.recvuntil(b"Text: ")
        c = int(sc.recvline())
        problem.append((c,n))

    sol = crt(problem)
    flag = int_nth_root(sol, 11)

    return long_to_bytes(flag)[:-16].decode()


if __name__ == "__main__":
    while True:
        flag = exploit()
        if flag is not None:
            print(flag)
            exit()