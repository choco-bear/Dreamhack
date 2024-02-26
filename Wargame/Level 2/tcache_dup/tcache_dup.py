# Name: tcache_dup.py

from pwn import *

def slog(name,addr): success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 0

p = remote(HOST,PORT)
