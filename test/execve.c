#include <unistd.h>

int main() {
  char *const args[] = {"-c", "echo I've run a shell!!"};
  execve("/bin/sh", args, NULL);
}

// Report: Bad system call