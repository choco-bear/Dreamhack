# Name: tcache_dup2.py

from pwn import *

def slog(name,addr): success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 0

p = remote(HOST,PORT)

#ifndef __Custom_Functions_For_Convenience_
#define __Custom_Functions_For_Convenience_
#endif /* __Custom_Functions_For_Convenience_ */

#ifndef __Custom_Global_Variables_For_Convenience_
#define __Custom_Global_Variables_For_Convenience_
dummy = b'A'
#endif /* __Custom_Global_Variables_For_Convenience_ */
