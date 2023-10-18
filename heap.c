#include "heap.h"
#include "custom_unistd.h"
#include <string.h>

#define STRUCT_SIZE sizeof(struct memory_chunk_t)
#define FENCE_SIZE 12
#define FEN_STR (STRUCT_SIZE + FENCE_SIZE)
#define FEN_STR_FEN (STRUCT_SIZE + FENCE_SIZE + FENCE_SIZE)
#define FENCE_HEAD 'M'
#define FENCE_TAIL 'B'

struct allocator_info_t allocator;


int heap_setup(void){
    if(allocator.memory_start != NULL) return -1;

    allocator.memory_start = custom_sbrk(0);
    if(allocator.memory_start == (void *) -1) return -1;

    allocator.first_chunk = NULL;
    allocator.last_chunk = NULL;
    allocator.memory_size = 0;

    return 0;
}

void heap_clean(void){
    custom_sbrk((intptr_t) - allocator.memory_size);
    allocator.memory_start = NULL;
    allocator.memory_size = 0;
    allocator.first_chunk = NULL;
    allocator.last_chunk = NULL;
}

int heap_validate(void){
    if(allocator.memory_start == NULL) return 2;

    struct memory_chunk_t *chunk_ptr = allocator.first_chunk;

    while(chunk_ptr){
        if(chunk_hash(chunk_ptr) != chunk_ptr->hash_value) return 3;
        if(chunk_ptr->free != 1){
            for(int i = 0; i < FENCE_SIZE; i++){
                if(*((uint8_t *)(chunk_ptr) + STRUCT_SIZE + i) != FENCE_HEAD) return 1;
                if(*((uint8_t *)(chunk_ptr) + FEN_STR + i + chunk_ptr->size ) != FENCE_TAIL) return 1;
            }
        }
        chunk_ptr = chunk_ptr->next;
    }
    return 0;
}

size_t heap_get_largest_used_block_size(void){
    if(heap_validate() > 0 || allocator.first_chunk == NULL) return 0;

    struct memory_chunk_t *chunk_ptr = allocator.first_chunk;
    size_t largest_size = 0;

    while (chunk_ptr){
        if(chunk_ptr->free == 0){
            if(largest_size < chunk_ptr->size) largest_size = chunk_ptr->size;
        }
        chunk_ptr = chunk_ptr->next;
    }

    return largest_size;
}

enum pointer_type_t get_pointer_type(const void* const pointer){
    if(pointer == NULL) return pointer_null;

    if(allocator.first_chunk == NULL) return pointer_unallocated;
    if(heap_validate() > 0) return pointer_heap_corrupted;

    struct memory_chunk_t *chunk_ptr = allocator.first_chunk;
    uint8_t *ui_pointer = (uint8_t *)pointer;

    while (chunk_ptr != NULL){
        if(chunk_ptr->free != 1) {
            uint8_t *ui_str_ptr = (uint8_t *)chunk_ptr;

            if (ui_str_ptr + FEN_STR == ui_pointer) return pointer_valid;
            if (ui_pointer >= ui_str_ptr && ui_pointer < ui_str_ptr + STRUCT_SIZE) return pointer_control_block;
            if (ui_pointer >= ui_str_ptr + STRUCT_SIZE && ui_pointer < ui_str_ptr + FEN_STR) return pointer_inside_fences;
            if (ui_pointer >= ui_str_ptr + FEN_STR && ui_pointer < ui_str_ptr + FEN_STR + chunk_ptr->size) return pointer_inside_data_block;
            if (ui_pointer >= ui_str_ptr + FEN_STR + chunk_ptr->size && ui_pointer < ui_str_ptr + FEN_STR_FEN + chunk_ptr->size) return pointer_inside_fences;
        }
        chunk_ptr = chunk_ptr->next;
    }

    return pointer_unallocated;
}


void set_fences(struct memory_chunk_t* chunk_ptr){
    if(allocator.first_chunk == NULL || chunk_ptr == NULL) return;

    memset(((uint8_t *)chunk_ptr + STRUCT_SIZE), FENCE_HEAD, FENCE_SIZE);
    memset(((uint8_t *)chunk_ptr + chunk_ptr->size + FEN_STR), FENCE_TAIL, FENCE_SIZE);
}

size_t chunk_hash(struct memory_chunk_t *chunk_ptr){
    if(chunk_ptr == NULL || allocator.first_chunk == NULL) return -1;
    
    size_t hash_value = 0;
    for (unsigned long i = 0; i < STRUCT_SIZE - sizeof(size_t); i++) {
        hash_value += *((uint8_t *) chunk_ptr + i);
    }

    return hash_value;
}

void connect_chunks(struct memory_chunk_t *first_chunk, struct memory_chunk_t *second_chunk){
    first_chunk->next = second_chunk->next;
    first_chunk->size += second_chunk->size + STRUCT_SIZE;
    first_chunk->end = first_chunk->begin + first_chunk->size;
    if(second_chunk->next != NULL){
        second_chunk->next->prev = first_chunk;
        second_chunk->next->hash_value = chunk_hash(second_chunk->next);
    }
    first_chunk->hash_value = chunk_hash(first_chunk);
}

void remove_end_free_chunks(){
    struct memory_chunk_t *chunk_to_remove = allocator.last_chunk;
    while (chunk_to_remove){
        if(chunk_to_remove->free == 0) break;
        if(chunk_to_remove->prev != NULL) {
            chunk_to_remove->prev->next = NULL;
            chunk_to_remove->prev->hash_value = chunk_hash(chunk_to_remove->prev);
        }
        chunk_to_remove = chunk_to_remove->prev;
    }
    allocator.last_chunk = chunk_to_remove;
    if(allocator.last_chunk == NULL) allocator.first_chunk = NULL;
}


void* heap_calloc(size_t number, size_t size) {
    if (heap_validate() > 0 || number == 0 || size == 0 || allocator.memory_start == NULL) return NULL;

    size_t new_size = number * size;
    void *new_chunk = heap_malloc(new_size);
    if (new_chunk != NULL) memset(new_chunk, 0, new_size);

    return new_chunk;
}

void* heap_malloc(size_t size){
    if(heap_validate() > 0 || size == 0 || allocator.memory_start == NULL) return NULL;

    size_t needed_size = FEN_STR_FEN + size;

    if(allocator.first_chunk == NULL){
        if(needed_size > allocator.memory_size) {
            void *new_chunk = custom_sbrk((intptr_t)(needed_size - allocator.memory_size));
            if (new_chunk == (void *) -1) return NULL;
            allocator.memory_size += (needed_size - allocator.memory_size);
        }
        struct memory_chunk_t *new_chunk = allocator.memory_start;
        allocator.first_chunk = new_chunk;
        allocator.last_chunk = new_chunk;
        new_chunk->free = 0;
        new_chunk->size = size;
        new_chunk->next = NULL;
        new_chunk->prev = NULL;
        new_chunk->begin = 0;
        new_chunk->end = needed_size;
        new_chunk->hash_value = chunk_hash(new_chunk);
        set_fences(new_chunk);
        return (uint8_t *)new_chunk + FEN_STR;
    }

    struct memory_chunk_t *chunk_ptr = allocator.first_chunk;

    while (chunk_ptr){
        if(chunk_ptr->free == 1 && chunk_ptr->size >= size + FENCE_SIZE + FENCE_SIZE){
            chunk_ptr->free = 0;
            chunk_ptr->end = chunk_ptr->begin + needed_size;
            chunk_ptr->size = size;
            chunk_ptr->hash_value = chunk_hash(chunk_ptr);
            set_fences(chunk_ptr);
            return (uint8_t *)chunk_ptr + FEN_STR;
        }
        chunk_ptr = chunk_ptr->next;
    }

    if(allocator.memory_size < allocator.last_chunk->end + needed_size){
        size_t missing_size = allocator.last_chunk->end + needed_size - allocator.memory_size;
        void *new_chunk = custom_sbrk((intptr_t) missing_size);
        if(new_chunk == (void *) -1) return NULL;
        allocator.memory_size += missing_size;
    }
    struct memory_chunk_t *new_chunk = (void *)((uint8_t *)allocator.memory_start + allocator.last_chunk->end);
    new_chunk->size = size;
    new_chunk->free = 0;
    new_chunk->next = NULL;
    new_chunk->begin = allocator.last_chunk->end;
    new_chunk->end = new_chunk->begin + needed_size;
    new_chunk->prev = allocator.last_chunk;
    allocator.last_chunk->next = new_chunk;
    allocator.last_chunk->hash_value = chunk_hash(allocator.last_chunk);
    new_chunk->hash_value = chunk_hash(new_chunk);
    set_fences(new_chunk);
    allocator.last_chunk = new_chunk;
    return (uint8_t *)new_chunk + FEN_STR;
}

void heap_free(void *memblock) {
    if (heap_validate() > 0 || memblock == NULL  || allocator.memory_start == NULL || allocator.first_chunk == NULL) return;

    struct memory_chunk_t *chunk_to_remove = (void *)((uint8_t *)memblock - FEN_STR);
    struct memory_chunk_t *chunk_ptr = allocator.first_chunk;

    while (chunk_ptr){
        if(chunk_ptr == chunk_to_remove) {
            chunk_to_remove->free = 1;

            if(chunk_to_remove->next == NULL){
                if(chunk_to_remove->prev == NULL){
                    allocator.first_chunk = NULL;
                    allocator.last_chunk = NULL;
                    return;
                }
                if(chunk_to_remove->prev != NULL){
                    remove_end_free_chunks();
                    return;
                }
            }

            chunk_to_remove->size += chunk_to_remove->next->begin - chunk_to_remove->end + FENCE_SIZE + FENCE_SIZE;
            chunk_to_remove->hash_value = chunk_hash(chunk_to_remove);

            if(chunk_to_remove->next != NULL){
                if(chunk_to_remove->next->free == 1) connect_chunks(chunk_to_remove, chunk_to_remove->next);
            }
            if(chunk_to_remove->prev != NULL){
                if(chunk_to_remove->prev->free == 1) connect_chunks(chunk_to_remove->prev, chunk_to_remove);
            }
            remove_end_free_chunks();
        }
        chunk_ptr = chunk_ptr->next;
    }
}

void* heap_realloc(void* memblock, size_t count){
    if(allocator.memory_start == NULL) return NULL;
    if(memblock == NULL && count == 0) return NULL;

    if(memblock == NULL) return heap_malloc(count);

    if(count == 0) {
        heap_free(memblock);
        return NULL;
    }

    struct memory_chunk_t *chunk_ptr = allocator.first_chunk;
    struct memory_chunk_t *chunk_ptr_from_function = (void *)((uint8_t *)memblock - FEN_STR);

    size_t needed_size = FEN_STR_FEN + count;

    while (chunk_ptr){
        if(chunk_ptr == chunk_ptr_from_function && chunk_ptr->free == 0) {

            if(chunk_ptr->next == NULL){
                if (allocator.memory_size < chunk_ptr->begin + needed_size) {
                    size_t missing_size = chunk_ptr->begin + needed_size - allocator.memory_size;
                    void *new_chunk = custom_sbrk((intptr_t) missing_size);
                    if (new_chunk == (void *) -1) return NULL;
                    allocator.memory_size += missing_size;
                }
                chunk_ptr->size = count;
                chunk_ptr->end = chunk_ptr->begin + needed_size;
                chunk_ptr->hash_value = chunk_hash(chunk_ptr);
                set_fences(chunk_ptr);
                return memblock;
            }

            if(chunk_ptr->next != NULL){
                if(chunk_ptr->next->free == 0){
                    if(chunk_ptr->next->begin - chunk_ptr->begin >= needed_size){
                        chunk_ptr->size = count;
                        chunk_ptr->end = chunk_ptr->begin + needed_size;
                        chunk_ptr->hash_value = chunk_hash(chunk_ptr);
                        set_fences(chunk_ptr);
                        return memblock;
                    }
                    if(chunk_ptr->next->begin - chunk_ptr->begin < needed_size){
                        void *new_chunk = heap_malloc(count);
                        if(new_chunk == NULL) return NULL;
                        memcpy(new_chunk, memblock, chunk_ptr->size);
                        heap_free(memblock);
                        return new_chunk;
                    }
                }

                if(chunk_ptr->next->free == 1){
                    if(chunk_ptr->next->end - chunk_ptr->begin >= needed_size){
                        struct memory_chunk_t *new_next_chunk = chunk_ptr->next->next;
                        chunk_ptr->size = chunk_ptr->next->end - chunk_ptr->begin;
                        chunk_ptr->next = new_next_chunk;
                        chunk_ptr->end = chunk_ptr->begin + needed_size;
                        chunk_ptr->size = count;
                        chunk_ptr->hash_value = chunk_hash(chunk_ptr);
                        new_next_chunk->prev = chunk_ptr;
                        new_next_chunk->hash_value = chunk_hash(new_next_chunk);
                        set_fences(chunk_ptr);
                        return memblock;
                    }

                    if(chunk_ptr->next->end - chunk_ptr->begin < needed_size){
                        void *new_chunk = heap_malloc(count);
                        if(new_chunk == NULL) return NULL;
                        memcpy(new_chunk, memblock, chunk_ptr->size);
                        heap_free(memblock);
                        return new_chunk;
                    }
                }
            }
        }
        chunk_ptr = chunk_ptr->next;
    }

    return NULL;
}

