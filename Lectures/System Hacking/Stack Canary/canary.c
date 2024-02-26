// Name: canary.c
#include <unistd.h>
int main() {
  char buf[8];
  read(0, buf, 32);
  return 0;
}