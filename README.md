# MemoryAllocator
Simple POSIX memory allocator in C.

## Custom_sbrk
The allocator uses a custom_sbrk function found in files `custom_unistd.h` and `memmanager.c`. The creator of the function: https://github.com/tomekjaworski/SO2/tree/master/heap_sbrk-sim.

## Description
Malloc, Calloc, Realloc and Free have a `heap_` prefix.
Functions include fences directly before and after the block allocated to the user. The purpose of these fences is to facilitate the detection of One-off errors, as each fence has specific and known content and length. A breach (alteration of its values) indicates that the user's code is incorrectly using the allocated memory block.

## How to use
At first, we have to initialize the heap with the `heap_setup()` function. After that, we can start allocating memory. Finally, we should use `heap_clean()`.
Example:
```c
#include "heap.h"

int main() {
    heap_setup();
    int *number = (int *)heap_malloc(sizeof(int));
    if (!number) {
        return 1;
    }
  
    heap_free(number);
    heap_clean();
    return 0;
}
```
