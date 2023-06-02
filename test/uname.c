#include <stdio.h>
#include <sys/utsname.h>

int main() {
  struct utsname info;
  if (uname(&info)) {
    printf("My OS is %s", info.sysname);
  }
}

// Report: Ok