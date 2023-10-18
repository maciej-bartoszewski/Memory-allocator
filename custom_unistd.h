/*
 * Emulacja funkcji systemowej sbrk() na potrzeby projektu alokatora pamięci przedmiotu Systemy Operacyjne 2.
 * Autor: Tomasz Jaworski, 2020
 */

#if !defined(_CUSTOM_UNISTD_H_)
#define _CUSTOM_UNISTD_H_

#include <unistd.h>
#include <stdint.h>

void* custom_sbrk(intptr_t delta);

#if defined(sbrk)
#undef sbrk
#endif

#if defined(brk)
#undef brk
#endif


#define sbrk(__arg__) (assert("Proszę nie używać standardowej funkcji sbrk()" && 0), (void*)-1)
#define brk(__arg__) (assert("Proszę nie używać standardowej funkcji sbrk()" && 0), -1)

int custom_sbrk_check_fences_integrity(void);

uint64_t custom_sbrk_get_reserved_memory(void);

#endif // _CUSTOM_UNISTD_H_

