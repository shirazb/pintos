
#include <threads/malloc.h>
#include <vm/frame.h>
#include <userprog/process.h>

static struct frame_table table;
static struct read_write_lock frame_table_rw_lock;


static struct frame_info *make_frame_info(enum palloc_flags flags, size_t index);

static hash_hash_func frame_hash_func;
static hash_less_func frame_less_func;


void frame_table_init() {
    table.used_frames = bitmap_create(TABLE_SIZE);
    rw_lock_init(&frame_table_rw_lock);
    hash_init(&table.frames, frame_hash_func, frame_less_func, NULL);
}

void frame_table_destroy() {

}

void frame_table_evict() {

}

void *frame_alloc_page(enum palloc_flags flags) {
    w_lock_acquire(&frame_table_rw_lock);
    size_t free_index = bitmap_scan_and_flip(table.used_frames, 0, 1, false);
    w_lock_release(&frame_table_rw_lock);

    struct frame_info *entry;

    if (free_index == BITMAP_ERROR) {
        // TODO: Eviction
        NOT_REACHED();
    }
    entry = make_frame_info(flags, free_index);

    w_lock_acquire(&frame_table_rw_lock);
    hash_insert(&table.frames, &entry->hash_elem);
    w_lock_release(&frame_table_rw_lock);

    struct page_num_entry *page_num_entry = malloc(sizeof(struct page_num_entry));
    page_num_entry->addr = entry->user_frame;
//    page_num_entry->page_num = process_current().;

    return entry->user_frame;
}

struct frame_info *make_frame_info(enum palloc_flags flags, size_t index) {
    struct frame_info *entry = malloc(sizeof(struct frame_info));
    entry->pid = thread_current()->tid;
    entry->user_frame = palloc_get_page(flags);
    entry->index = index;
    return entry;
}

void frame_free_page(void *addr, struct process *p) {
    // find the frame information mapped from the process page table
    struct frame_info search_info;
    search_info.pid = p->pid;
    search_info.page_num = get_page_num(&p->sp_table, addr);

    w_lock_acquire(&frame_table_rw_lock);
    struct hash_elem *e = hash_delete(&table.frames, &search_info.hash_elem);

    // TODO: freeing a swapped out page should clear the swap table of the entry
    if (!e) {
        NOT_REACHED();
    }

    struct frame_info *entry = hash_entry(e, struct frame_info, hash_elem);

    // set the bit for the frame to unallocated
    bitmap_flip(table.used_frames, entry->index);
    w_lock_release(&frame_table_rw_lock);

    // free the page in virtual memory and the entry
    palloc_free_page(entry->user_frame);
    free(entry);
}

// frame hashing function using the process ID (tid) and the page number
unsigned frame_hash_func(const struct hash_elem *e, void *aux UNUSED) {
    struct frame_info *entry = hash_entry(e, struct frame_info, hash_elem);
    tid_t tid = entry->pid;
    unsigned page_num = (unsigned) entry->page_num;
    return (tid + page_num) * (tid + page_num + 1) / 2 + tid;
}

bool frame_less_func(const struct hash_elem *a,
                     const struct hash_elem *b,
                     void *aux UNUSED) {
    struct frame_info *e1 = hash_entry(a, struct frame_info, hash_elem);
    struct frame_info *e2 = hash_entry(b, struct frame_info, hash_elem);

    return e1->index < e2->index;
}
