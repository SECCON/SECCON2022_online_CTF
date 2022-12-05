enc = [
    int.to_bytes(0x5894a5af7f7693b7, 8, 'little'),
    int.to_bytes(0x94706b86ce8e1cce, 8, 'little'),
    int.to_bytes(0x0098ba6f1ff3cc98, 8, 'little'),
    int.to_bytes(0x0ae6575961af354c, 8, 'little'),
    int.to_bytes(0xd853f981df45ab41, 8, 'little'),
    int.to_bytes(0xe1fefd554e662f7f, 8, 'little'),
    int.to_bytes(0x3ca11fb09e498ab4, 8, 'little'),
]
key = b"\x11\x45\x14\x19\x19\x81\x09\x31\x88\x94\x64\x51\x28\x10\x93\x15"
sbox = b"\x0C\x00\x0F\x0A\x02\x0B\x09\x05\x08\x03\x0D\x07\x01\x0E\x06\x04"
roundconst = b"\x01\x02\x04\x08\x10\x20\x03\x06\x0c\x18\x30\x23\x05\x0a\x14\x28\x13\x26\x0f\x1e\x3c\x3b\x35\x29\x11\x22\x07\x0e\x1c\x38\x33\x25\x09\x12\x24\x0b"

# Expand key (you can also check memory for `rk` instead of emulating it)
rk = [None for i in range(36)]
wk = []
for c in key:
    wk.append(c >> 4)
    wk.append(c & 0xf)

for i in range(35):
    rk[i] = [wk[31], wk[28], wk[18], wk[17], wk[15], wk[12], wk[3], wk[2]]
    wk[1] ^= sbox[wk[30]]
    wk[4] ^= sbox[wk[16]]
    wk[23] ^= sbox[wk[0]]
    con = roundconst[i]
    wk[19] ^= con >> 3
    wk[7] ^= con & 7

    ts = list(wk[0:4])
    for j in  range(7):
        wk[j*4+0] = wk[j*4+4]
        wk[j*4+1] = wk[j*4+5]
        wk[j*4+2] = wk[j*4+6]
        wk[j*4+3] = wk[j*4+7]
    wk[28:32] = [ts[1], ts[2], ts[3], ts[0]]

rk[35] = [wk[3], wk[2], wk[15], wk[12], wk[18], wk[17], wk[31], wk[28]]

# Decrypt
shufinv = [1, 2, 11, 6, 3, 0, 9, 4, 7, 10, 13, 14, 5, 8, 15, 12]
flag = b""
for e in enc:
    x = []
    for i in range(8):
        x.append(e[i] >> 4)
        x.append(e[i] & 0xf)

    for i in range(35, 0, -1):
        for j in range(8):
            x[2*j+1] ^= sbox[x[2*j] ^ rk[i][j]]

        xprev = [0] * 16
        for j in range(16):
            xprev[shufinv[j]] = x[j]
        x = xprev

    for j in range(8):
        x[2*j+1] ^= sbox[x[2*j] ^ rk[0][j]]

    for i in range(8):
        flag += bytes([x[2*i] << 4 | x[2*i+1]])

print(flag)
