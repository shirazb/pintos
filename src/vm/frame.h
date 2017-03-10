#ifndef PINTOS_36_FRAME_H
#define PINTOS_36_FRAME_H

#include "lib/kernel/hash.h"
#include "lib/kernel/bitmap.h"
#include "threads/thread.h"

#define NUM_FRAMES ((2 << 21) - 1)

struct frame_info {
    tid_t tid;
    int page_num;
};

struct frame_table {
    struct frame_info frames[NUM_FRAMES];
    struct bitmap *used_frames;
};

void frame_table_init();
void frame_table_deinit();
void frame_table_evict();


#endif //PINTOS_36_FRAME_H
