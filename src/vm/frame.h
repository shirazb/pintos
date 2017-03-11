#ifndef PINTOS_36_FRAME_H
#define PINTOS_36_FRAME_H

#include <hash.h>
#include <threads/palloc.h>

struct frame {
    void *kpage;                    /* Kernel page. */
    void *upage;                    /* User page that maps to the kernel page. */
    struct thread *thread_used_by;  /* Tgread that owns the user page. */
    struct hash_elem ft_elem;          /* To put in the frame table. */
};

struct frame *ft_init_new_frame(enum palloc_flags flags, void *upage); // return an unused frame, NULL if no unused frame exists.
struct frame *ft_evict_frame(void);  // pick a frame to evict, remove it from FT and return it.


#endif //PINTOS_36_FRAME_H
