#ifndef PINTOS_36_FRAME_H
#define PINTOS_36_FRAME_H

#include <hash.h>
#include <threads/palloc.h>

/* A kpage -> upage mapping in the frame table. */
struct frame {
    size_t index;                   /* Index of frame in the bitmap. */
    void *kpage;                    /* Kernel page. */
    void *upage;                    /* User page that maps to the kernel page in the process' page table. */
    struct thread *thread_used_by;  /* Thread that owns the user page. */
    struct hash_elem hash_elem;     /* To put in the frame table. */
};


void ft_init(void);
struct frame *ft_init_new_frame(enum palloc_flags flags, void *upage); // return an unused frame, NULL if no unused frame exists.
struct frame *ft_evict_frame(void);  // pick a frame to evict, remove it from FT and return it.
struct frame *ft_lookup(void *kpage);
void ft_remove(struct frame *frame);
void ft_destroy(struct frame *frame);

#endif //PINTOS_36_FRAME_H
