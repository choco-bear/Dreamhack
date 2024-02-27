# Name: tcache_dup2.py

from pwn import *

def slog(name,addr): success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 0

# p = remote(HOST,PORT) # remote
p = process('./tcache_dup2', env={'LD_PRELOAD':'./libc-2.30.so'}) # local


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
#endif /* __Custom_Global_Variables_For_Convenience_ */
