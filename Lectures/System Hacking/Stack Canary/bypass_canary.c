// Name: bypass_canary.c
// Compile: gcc -o bypass_canary bypass_canary.c
#include <stdio.h>
#include <unistd.h>
int main() {
  char memo[8];
  char name[8];
  printf("name : ");
  read(0, name, 64);
  printf("hello %s\n", name);
  printf("memo : ");
  read(0, memo, 64);
  printf("memo %s\n", memo);
  return 0;
} 