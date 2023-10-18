#ifndef PROJECT1_HEAP_H
#define PROJECT1_HEAP_H
#include <stdio.h>

struct allocator_info_t {
    void *memory_start;
    size_t memory_size;
    struct memory_chunk_t *first_chunk;
    struct memory_chunk_t *last_chunk;
};

struct memory_chunk_t {
    struct memory_chunk_t *prev;
    struct memory_chunk_t *next;
    unsigned free;
    size_t size;
    size_t begin;
    size_t end;
    size_t hash_value;
};

enum pointer_type_t
{
    pointer_null,
    pointer_heap_corrupted,
    pointer_control_block,
    pointer_inside_fences,
    pointer_inside_data_block,
    pointer_unallocated,
    pointer_valid
};

void set_fences(struct memory_chunk_t* chunk_ptr);
size_t chunk_hash(struct memory_chunk_t *chunk_ptr);
void connect_chunks(struct memory_chunk_t *first_chunk, struct memory_chunk_t *second_chunk);
void remove_end_free_chunks();

int heap_setup(void);
void heap_clean(void);
int heap_validate(void);

size_t heap_get_largest_used_block_size(void);
enum pointer_type_t get_pointer_type(const void* const pointer);

void* heap_malloc(size_t size);
void* heap_calloc(size_t number, size_t size);
void* heap_realloc(void* memblock, size_t count);
void  heap_free(void* memblock);


#endif //PROJECT1_HEAP_H
