#include <stdio.h>

int main() {
  const char *junk = "output 10 Mega-Bytes ";
  for (int i = 0; i < 10 * 1024 * 1024; i += sizeof(junk)) {
    printf("%s", junk);
  }
}

// Report: Output size exceeded