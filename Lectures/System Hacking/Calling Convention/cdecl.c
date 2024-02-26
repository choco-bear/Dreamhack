// Name: cdecl.c
// Compile: gcc -fno-asynchronous-unwind-tables -nostdlib -masm=intel \
//          -fomit-frame-pointer -S cdecl.c -w -m32 -fno-pic -O0

void __attribute__((cdecl)) callee(int a1, int a2){ // cdecl로 호출
}

void caller(){
   callee(1, 2);
}