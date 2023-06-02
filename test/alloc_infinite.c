#include <stdlib.h>
#include <stdint.h>

int main() {
  const int block_size = 1024 * 1024; // 1MB
  for (;;) {
    // Allocate 1KB and set to 0
    uint8_t *bytes = malloc(block_size);
    for (int j = 0; j < block_size; j++) {
      *bytes++ = 0;
    }
  }
}

// Report: Segmentation Fault