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

/*
 * Creates a new entry in the swap table with the given thread and user page.
 * Copies the given kernel page into a free swap slot.
 * Returns the index of that swap slot.
 */
size_t
st_new_swap_entry(struct thread *thread_used_by, void *upage, void *kpage) {
    struct swap_slot *new_slot = malloc(sizeof(struct swap_slot));
    ASSERT(new_slot);

    size_t slot_idx = bitmap_scan_and_flip(st.used_slots, 0, 1, false);
    if (slot_idx == BITMAP_ERROR) {
        PANIC("Exhausted swap space!");
    }

    new_slot->thread_used_by = thread_used_by;
    new_slot->index = slot_idx;
    new_slot->upage = upage;
    write_to_swap(new_slot->index, kpage);

    return slot_idx;
}


/*
 * Writes the kpage to the swap slot indexed by the given slot_index.
 */
static void
write_to_swap(size_t slot_index, void *kpage) {
    ASSERT(kpage != NULL);

    for (int i = 0; i < SECTORS_PER_PAGE; i++) {
        block_sector_t sector = (block_sector_t) (slot_index * SECTORS_PER_PAGE + i);
        block_write(st.swap_block, sector, kpage);
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
        block_read(st.swap_block, sector, kpage);
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
