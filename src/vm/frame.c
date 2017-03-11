#include <vm/frame.h>
#include <bitmap.h>
#include <threads/malloc.h>
#include <threads/thread.h>
#include <userprog/process.h>

#define NUM_FRAMES (2 << 22)

static struct frame_table {
    struct hash table; // Map<*k_page, *u_page>
    struct bitmap *used_frames;
};

static struct frame_table ft;


void ft_init(void) {
    ft.used_frames = bitmap_create(NUM_FRAMES);
    // TODO: DO
    hash_init(&ft.table, NULL, NULL, NULL);
}

// TODO: synch
struct frame *ft_init_new_frame(enum palloc_flags flags, void *upage) {
    size_t frame_index = bitmap_scan_and_flip(ft.used_frames, 0, 1, false);

    if (frame_index == BITMAP_ERROR) {
        return NULL;
    }

    struct frame *new_frame = malloc(sizeof(struct frame));
    if (!new_frame) {
        process_exit();
        NOT_REACHED();
    }

    new_frame->thread_used_by = thread_current();
    new_frame->upage = upage;
    new_frame->kpage = palloc_get_page(flags);
    ASSERT(new_frame->kpage != NULL);

    hash_insert(&ft.table, &new_frame->hash_elem);

    return new_frame;
}
