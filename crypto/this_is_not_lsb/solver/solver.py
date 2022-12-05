import socket
import base64
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((os.getenv("SECCON_HOST"), int(os.getenv("SECCON_PORT"))))
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
msg = s.recv(1024)
msg = msg.split(b'\n')
n = int(msg[0].split()[-1])
e = int(msg[1].split()[-1])
flag_length = int(msg[2].split()[-1])
c = int(msg[3].split()[-1])
n,flag_length,e,c

def oracle(c):
    s.send((str(c)+"\n").encode())
    return b"True" in s.recv(1024)

oracle(c)

ok = False
padding_pos = n.bit_length() - 2

i = padding_pos-flag_length-8
z = 2**i
res = 0
while not oracle(c*pow((z+res),e,n) % n):
    res += z

while True:
    if oracle(c*pow((z+res),e,n)):
        res += z
        z *= 2
    z //= 2
    if z == 1:
        break

print(bytes.fromhex(hex(2 ** padding_pos // res)[2:]).decode('utf-8'))
