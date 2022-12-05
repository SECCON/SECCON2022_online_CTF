import socket
import base64
from Crypto.Util.number import *
from pydoc import plain
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
import gcm
import time
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.connect(("localhost", int(8080)))
s.connect((os.getenv("SECCON_HOST"), int(os.getenv("SECCON_PORT"))))
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

def decrypt(c):
    s.send(c.hex().encode('utf-8') + b"\n")
    res = s.recv(1024)
    return res

def decrypt_oracle(c):
    org_c = c
    gcm_ciphertext = b""

    c = org_c
    while (len(c) >= 32):
        for j in range(15,-1,-1):
            cprev, clast = c[:-16], c[-16:]

            prev = clast[:j]
            target = clast[j]
            nxt = clast[(j+1):]

            for i in range(255,-1,-1):
                cand = prev + bytes([target ^ i]) + nxt

                if b"ofb error" not in decrypt(cprev + cand):
                    # c ^ target ^ i == 0x01
                    gcm_ciphertext += bytes([(16-j) ^ i])
                    break
            
            o = b"\x00" * (j) + bytes([16-j]*(16-j))
            n = b"\x00" * (j) + bytes([16-j+1]*(16-j))
            next_last = strxor(cand, strxor(o,n))
            c = cprev + next_last
        c = c[:-16]

    return gcm_ciphertext[::-1]

def encrypt_oracle(K, m):
    c = m + b"\x00" * 16

    for j in range(15,-1,-1):
        cprev, clast = c[:-16], c[-16:]

        prev = clast[:j]
        target = clast[j]
        nxt = clast[(j+1):]

        for i in range(255,-1,-1):
            cand = prev + bytes([target ^ i]) + nxt

            if b"ofb error" not in decrypt(cprev + cand):
                break
        
        if j == 0:
            return strxor(cand, b"\x10" * 16)
        
        o = b"\x00" * (j) + bytes([16-j]*(16-j))
        n = b"\x00" * (j) + bytes([16-j+1]*(16-j))
        next_last = strxor(cand, strxor(o,n))
        c = cprev + next_last

msg = s.recv(1024)
msg = msg.split()
c = bytes.fromhex(msg[1].decode('utf-8'))

ofb_input = decrypt_oracle(c)
ofb_input = unpad(ofb_input, 16)
gcm_tag = ofb_input[:16]
gcm_nonce = ofb_input[16:32]
gcm_ciphertext = ofb_input[32:]
plain_text, _ = gcm.decrypt(gcm_ciphertext, b"", gcm_nonce, b"", encrypt_oracle)

gcm_ciphertext, gcm_tag = gcm.encrypt(b"give me key", b"", gcm_nonce, b"", encrypt_oracle)
ofb_input = b"\x00"*16 + pad(gcm_tag + gcm_nonce + gcm_ciphertext, 16)

c = decrypt_oracle(ofb_input)
print(decrypt(b"\x00"*16 + c))
print(plain_text)
s.send(plain_text + b"\n")
print(s.recv(1024).decode('utf-8'))
