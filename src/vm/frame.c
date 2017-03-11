#include <vm/frame.h>



static struct frame_table {
    struct hash frames; // Map<*k_page, *u_page>
    struct bitmap *used_frames;
};

static struct frame_table frame_table;
