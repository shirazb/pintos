#include <vm/frame.h>
#include <bitmap.h>
#include <threads/malloc.h>
#include <threads/thread.h>
#include <userprog/process.h>
#include <stdio.h>
#include <threads/vaddr.h>

#define NUM_FRAMES (2 << 20)

static void lock_ft(void);

static void unlock_ft(void);

static hash_hash_func frame_hash;
static hash_less_func frame_less;

static struct frame *pick_frame_to_evict(void);

static struct frame_table {
    struct lock lock;
    struct hash table; // Map<*k_page, *frame>
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
    lock_init(&ft.lock);
    hash_init(&ft.table, frame_hash, frame_less, NULL);
    ft.used_frames = bitmap_create(NUM_FRAMES);
}

struct frame *ft_init_new_frame(enum palloc_flags flags, void *upage) {
    ASSERT(is_page_aligned(upage));
    lock_ft();
    size_t frame_index = bitmap_scan_and_flip(ft.used_frames, 0, 1, false);
    unlock_ft();

    if (frame_index == BITMAP_ERROR) {
        return NULL;
    }

    struct frame *new_frame = malloc(sizeof(struct frame));
    ASSERT(new_frame != NULL);

    new_frame->index = frame_index;
    new_frame->kpage = palloc_get_page(flags);
    new_frame->upage = upage;
    new_frame->thread_used_by = thread_current();
    ASSERT(new_frame->kpage != NULL);

    lock_ft();
    hash_insert(&ft.table, &new_frame->hash_elem);
    unlock_ft();

    return new_frame;
}

struct frame *ft_lookup(void *kpage) {
    struct frame search_frame;
    search_frame.kpage = kpage;

    lock_ft();
    struct hash_elem *found_elem = hash_find(&ft.table, &search_frame.hash_elem);
    unlock_ft();
    ASSERT(found_elem);

    return hash_entry(found_elem, struct frame, hash_elem);

}

void ft_remove(struct frame *frame) {
    lock_ft();
    bitmap_flip(ft.used_frames, frame->index);
    ASSERT(bitmap_test(ft.used_frames, frame->index) == 0);
    hash_delete(&ft.table, &frame->hash_elem);
    unlock_ft();

    palloc_free_page(frame->kpage);
}

void ft_destroy(struct frame *frame) {
    ft_remove(frame);
    free(frame);
}

struct frame *ft_evict_frame(void) {
    struct frame *to_evict = pick_frame_to_evict();

    ft_remove(to_evict);
    return to_evict;
}

// TODO: Implement a proper eviction algorithm.
static struct frame *pick_frame_to_evict(void) {
    struct hash_iterator it;
    lock_ft();
    hash_first(&it, &ft.table);
    struct hash_elem *e = hash_next(&it);
    unlock_ft();

    return hash_entry(e, struct frame, hash_elem);
}

unsigned frame_hash(const struct hash_elem *e, void *aux UNUSED) {
    struct frame *frame = hash_entry(e, struct frame, hash_elem);
    return (unsigned) frame->kpage;
}

bool frame_less(const struct hash_elem *a, const struct hash_elem *b,
                void *aux UNUSED) {
    struct frame *f1 = hash_entry(a, struct frame, hash_elem);
    struct frame *f2 = hash_entry(b, struct frame, hash_elem);
    return f1->kpage < f2->kpage;
}

