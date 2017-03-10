#ifndef PINTOS_36_FRAME_H
#define PINTOS_36_FRAME_H

#include "lib/kernel/hash.h"
#include "lib/kernel/bitmap.h"
#include "threads/thread.h"

#define NUM_FRAMES ((2 << 21) - 1)

struct page_info {
    tid_t tid[NUM_FRAMES];
    int page_num;
};

struct frame_table {
    struct page_info
    struct bitmap *used_frames;
};

void frame_table_init();
void frame_table_deinit();


#endif //PINTOS_36_FRAME_H
