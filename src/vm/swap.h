#ifndef PINTOS_36_SWAP_H
#define PINTOS_36_SWAP_H

#include <devices/block.h>
#include <lib/kernel/hash.h>
#include <threads/thread.h>

struct swap_slot {
    size_t index;                  /* Index into the swap table. */
    void *upage;                   /* Userpage that has been put into the swap slot. */
    struct thread *thread_used_by; /* The thread who owns the user page. */
    struct hash_elem st_elem;      /* To put in the swap table. */
};

void st_init(void);

size_t st_new_swap_entry(struct thread *thread_used_by, void *upage, void *kpage);

#endif
