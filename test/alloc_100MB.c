#include <stdlib.h>
#include <stdint.h>

int main() {
  const int total_size = 100 * 1024 * 1024; // 10MB
  const int block_size = 1024 * 1024; // 16KB
  for (int i = 0; i < total_size; i += block_size) {
    // Allocate 1KB and set to 0
    uint8_t *bytes = malloc(block_size);
    for (int j = 0; j < block_size; j++) {
      *bytes++ = 0;
    }
  }
}

// Report: Segmentation Fault