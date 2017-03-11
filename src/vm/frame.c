#include <vm/frame.h>
#include <bitmap.h>
#include <threads/malloc.h>
#include <threads/thread.h>
#include <userprog/process.h>

#define NUM_FRAMES (2 << 22)

static void lock_ft(void);

static void unlock_ft(void);

static struct frame_table {
    struct lock lock;
    struct hash table; // Map<*k_page, *u_page>
    struct bitmap *used_frames;
};

static struct frame_table ft;

void lock_ft(void) {
    lock_acquire(&ft.lock);
}
void unlock_ft(void) {
    lock_release(&ft.lock);
}

void ft_init(void) {
    ft.used_frames = bitmap_create(NUM_FRAMES);
    lock_init(&ft.lock);
    // TODO: DO
    hash_init(&ft.table, NULL, NULL, NULL);
}

struct frame *ft_init_new_frame(enum palloc_flags flags, void *upage) {
    lock_ft();
    size_t frame_index = bitmap_scan_and_flip(ft.used_frames, 0, 1, false);
    unlock_ft();

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

    lock_ft();
    hash_insert(&ft.table, &new_frame->hash_elem);
    unlock_ft();

    return new_frame;
}
