#include <stdio.h>
#include <stdlib.h>

int main() {
  FILE *file = fopen("some-file", "r");
  if (file == NULL) {
    fprintf(stderr, "File 'some-file' not present!");
    return 1;
  }
  int x;
  fscanf(file, "%d", &x);
  printf("Result: %d", x + 1);
}

// Report: Bad system call