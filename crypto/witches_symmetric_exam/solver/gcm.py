from gfpoly import GFPolynomial
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
import struct

# p.7
def ghash(H: bytes,A: bytes,C: bytes):
    lenA = len(A) * 8
    lenC = len(C) * 8
    A += b"\x00" * (16 - (len(A) % 16)) if len(A) % 16 != 0 else b""
    C += b"\x00" * (16 - (len(C) % 16)) if len(C) % 16 != 0 else b""

    As = [GFPolynomial(bytes_to_long(A[i:i + 16]), 128) for i in range(0, len(A), 16)]
    Cs = [GFPolynomial(bytes_to_long(C[i:i + 16]), 128) for i in range(0, len(C), 16)]
    H = GFPolynomial(bytes_to_long(H), 128)
    m = len(As)
    n = len(Cs)
    Xs = [GFPolynomial(0, 128)] * (m+n+2)
    for i in range(1,m+1):
        Xs[i] = (Xs[i-1] + As[i-1]) * H
    for i in range(1,n+1):
        Xs[m+i] = (Xs[m+i-1] + Cs[i-1]) * H
    res = (Xs[m+n] + (GFPolynomial(((lenA << 64) + lenC), 128))) * H
    return res.coeffs.to_bytes(16, byteorder="big")

def block_encrypt(K: bytes, msg: bytes) -> bytes:
    aes = AES.new(K, AES.MODE_ECB)
    return aes.encrypt(msg)

def incr(Y: bytes) -> bytes:
    F, I = Y[:-4], Y[-4:]
    I = ((bytes_to_long(I) + 1) % (1 << 32)).to_bytes(4, byteorder="big")

    return F + I

def bytes_xor(lhs: bytes, rhs: bytes) -> bytes:
    lhs = bytes_to_long(lhs)
    rhs = bytes_to_long(rhs)
    return long_to_bytes(lhs ^ rhs)

def encrypt(P: bytes, K: bytes, IV: bytes, A: bytes, block_encrypt):
    H = block_encrypt(K, b'\x00'*16)

    Ps = [P[i:i + 16] for i in range(0, len(P), 16)]
    n = len(Ps)

    Ys = [0]*(n+1) # note: Y[i] means Y_{i}
    if len(IV) == 12: # if len(IV) == 96bit
        Ys[0] = IV + b"\x00\x00\x00\x01"
    else:
        Ys[0] = ghash(H, b"", IV)
    for i in range(1, n+1):
        Ys[i] = incr(Ys[i-1])
    
    Cs = [b""] * n
    for i in range(n-1):
        # C_{i} = P_{i} XOR E(K, Y_{i})
        Cs[i] = bytes_xor(Ps[i], block_encrypt(K, Ys[i+1]))
    
    u = len(Ps[n-1])
    Cs[n-1] = bytes_xor(Ps[n-1], block_encrypt(K, Ys[n])[:u])

    C = b"".join(Cs)

    T = bytes_xor(ghash(H, A, C), block_encrypt(K, Ys[0]))

    return C, T

def decrypt(C: bytes, K: bytes, IV: bytes, A: bytes, block_encrypt):
    H = block_encrypt(K, b'\x00'*16)

    Cs = [C[i:i + 16] for i in range(0, len(C), 16)]
    n = len(Cs)

    Ys = [0]*(n+1) # note: Y[i] means Y_{i}
    if len(IV) == 12: # if len(IV) == 96bit
        Ys[0] = IV + b"\x00\x00\x00\x01"
    else:
        Ys[0] = ghash(H, b"", IV)
    for i in range(1, n+1):
        Ys[i] = incr(Ys[i-1])
    
    T = bytes_xor(ghash(H, A, C), block_encrypt(K, Ys[0]))
    
    Ps = [b""] * n
    for i in range(n-1):
        # C_{i} = P_{i} XOR E(K, Y_{i})
        Ps[i] = bytes_xor(Cs[i], block_encrypt(K, Ys[i+1]))
    
    u = len(Cs[n-1])
    Ps[n-1] = bytes_xor(Cs[n-1], block_encrypt(K, Ys[n])[:u])

    P = b"".join(Ps)

    return P, T
