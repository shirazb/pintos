// TODO:
/*  Helper to allocate new swap space for new entry
 *  Helper to free swap space for deleted entry
 *
 *  Main to swap a frame and swap entry
 */

#include "swap.h"
#include <lib/kernel/bitmap.h>
#include <threads/synch.h>
#include <threads/vaddr.h>
#include <threads/malloc.h>
#include <threads/palloc.h>

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

static struct swap_table {
    struct hash table;
    struct block *swap_block;
    struct bitmap *used_slots;
    struct lock lock;
};

/* Swap slot hashing. */
static hash_hash_func swap_slot_hash;
static hash_less_func swap_slot_less;

/* Reading and writing to the swap space. */
static void write_to_swap(size_t slot_index, void *kpage);
static void read_from_swap(size_t slot_index, void *kpage);

/* Synchronisation of swap table. */
static void lock_st(void);
static void unlock_st(void);

/* The global swap table. */
static struct swap_table st;

void
st_init(void) {
    hash_init(&st.table, swap_slot_hash, swap_slot_less, NULL);
    st.swap_block = block_get_role(BLOCK_SWAP);
    const size_t num_slots = block_size(st.swap_block) / SECTORS_PER_PAGE;
    st.used_slots = bitmap_create(num_slots);
    lock_init(&st.lock);
}

void
lock_st(void) {
    lock_acquire(&st.lock);
}

void
unlock_st(void) {
    lock_release(&st.lock);
}

/*
 * Move the page stored in the swap slot of the given index into the given
 * kernel page. Updates the swap table to reflect this change.
 */
void
st_swap_into_kpage(size_t index, void *kpage) {
    lock_st();

    // Reset this swap slot's bit in the bitmap.
    bitmap_flip(st.used_slots, index);
    ASSERT(bitmap_test(st.used_slots, index) == 0);

    // Remove corresponding swap entry from hash table.
    struct swap_slot to_delete;
    to_delete.index = index;
    struct hash_elem *deleted = hash_delete(
            &st.table,
            &to_delete.st_elem
    );
    ASSERT(deleted != NULL);

    unlock_st();

    read_from_swap(index, kpage);
}

/*
 * Creates a new entry in the swap table with the given thread and user page.
 * Copies the given kernel page into a free swap slot.
 * Returns the index of that swap slot.
 */
size_t
st_swap_out_kpage(struct thread *thread_used_by, void *upage, void *kpage) {
    struct swap_slot *new_slot = malloc(sizeof(struct swap_slot));
    ASSERT(new_slot);

    lock_st();
    size_t slot_idx = bitmap_scan_and_flip(st.used_slots, 0, 1, false);
    if (slot_idx == BITMAP_ERROR) {
        PANIC("Exhausted swap space!");
    }

    new_slot->thread_used_by = thread_used_by;
    new_slot->index = slot_idx;
    new_slot->upage = upage;

    struct hash_elem *prev_entry = hash_insert(&st.table, &new_slot->st_elem);
    ASSERT(prev_entry == NULL);
    
    unlock_st();
    write_to_swap(new_slot->index, kpage);
    palloc_free_page(kpage);

    return slot_idx;
}

void st_free_swap_entry(size_t index) {
    lock_st();

    bitmap_flip(st.used_slots, index);
    ASSERT(bitmap_test(st.used_slots, index) == 0);

    struct swap_slot search_slot;
    search_slot.index = index;

    struct hash_elem *e = hash_delete(&st.table, &search_slot.st_elem);
    ASSERT(e);

    unlock_st();

    struct swap_slot *slot = hash_entry(e, struct swap_slot, st_elem);
    free(slot);
}

/*
 * Writes the kpage to the swap slot indexed by the given slot_index.
 */
static void
write_to_swap(size_t slot_index, void *kpage) {
    ASSERT(kpage != NULL);

    for (int i = 0; i < SECTORS_PER_PAGE; i++) {
        block_sector_t sector = (block_sector_t) (slot_index * SECTORS_PER_PAGE + i);
        block_write(st.swap_block, sector, kpage + (i * BLOCK_SECTOR_SIZE));
    }
}

/*
 * Reads the the swap slot indexed by the given slot_index into the given
 * kernel page.
 */
static void
read_from_swap(size_t slot_index, void *kpage) {
    ASSERT(kpage != NULL);

    for (int i = 0; i < SECTORS_PER_PAGE; i++) {
        block_sector_t sector = (block_sector_t) (slot_index * SECTORS_PER_PAGE + i);
        block_read(st.swap_block, sector, kpage + (i * BLOCK_SECTOR_SIZE));
    }
}

unsigned
swap_slot_hash(const struct hash_elem *e, void *aux UNUSED) {
    struct swap_slot *slot = hash_entry(e, struct swap_slot, st_elem);
    return (unsigned) slot->index;
}

bool
swap_slot_less(const struct hash_elem *a, const struct hash_elem *b,
               void *aux UNUSED) {
    struct swap_slot *slot1 = hash_entry(a, struct swap_slot, st_elem);
    struct swap_slot *slot2 = hash_entry(b, struct swap_slot, st_elem);
    return slot1->index < slot2->index;
}
