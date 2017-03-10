#ifndef PINTOS_36_FRAME_H
#define PINTOS_36_FRAME_H

#include "lib/kernel/hash.h"
#include "lib/kernel/bitmap.h"
#include "threads/thread.h"

#define NUM_FRAMES ((2 << 21) - 1)
#define TABLE_SIZE (4 << 20)

struct frame_info {
    tid_t tid;
    size_t page_num;
    void * vaddr_page;
    size_t index;
    struct hash_elem hash_elem;
};

struct frame_table {
    struct hash frames; // Map<frame_index, frame_info>
    struct bitmap *used_frames;
};

// TODO: make private?
void frame_table_init();
void frame_table_deinit();
void frame_table_evict();


void * frame_alloc_page(size_t page_num);
void frame_free_page(tid_t tid, size_t page_num);


#endif //PINTOS_36_FRAME_H
