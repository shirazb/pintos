#include <threads/malloc.h>
#include <userprog/process.h>
#include <threads/vaddr.h>
#include <stdio.h>

static hash_hash_func user_location_hash_func;
static hash_less_func user_location_less_func;
static hash_action_func user_location_destroy;

void sp_table_init(struct sp_table *sp_table) {
    enum intr_level old_level = intr_disable();
    rec_lock_init(&sp_table->lock);
    hash_init(&sp_table->page_locs, user_location_hash_func, user_location_less_func, NULL);
    intr_set_level(old_level);
}


void sp_add_entry(struct sp_table *sp_table, void *upage, void *location,
                  enum location_type location_type
) {
    ASSERT(sp_table);
    ASSERT(upage);
    ASSERT(location);
    ASSERT(is_page_aligned(upage));
//    printf("adding %i 0x%08x\n", location_type, (unsigned int) upage);

    struct user_page_location *upl = malloc(sizeof(struct user_page_location));
    ASSERT(upl);

    upl->upage = upage;
    upl->location = location;
    upl->location_type = location_type;

    rec_lock_acquire(&sp_table->lock);
    hash_insert(&sp_table->page_locs, &upl->hash_elem);
    rec_lock_release(&sp_table->lock);
}


void sp_remove_entry(struct sp_table *sp_table, void *upage) {
    ASSERT(is_page_aligned(upage));
//    printf("removing 0x%08x\n", (unsigned int) upage);

    struct user_page_location search_upl;
    search_upl.upage = upage;

    rec_lock_acquire(&sp_table->lock);
    struct hash_elem *e = hash_delete(&sp_table->page_locs, &search_upl.hash_elem);
    rec_lock_release(&sp_table->lock);
    ASSERT(e);

    user_location_destroy(e, NULL);
}

void sp_update_entry(
        struct sp_table *sp_table,
        void *upage,
        void *new_location,
        enum location_type new_location_type
) {
    ASSERT(is_page_aligned(upage));
    struct user_page_location search_upl;
    search_upl.upage = upage;

    rec_lock_acquire(&sp_table->lock);
    struct hash_elem *found_elem = hash_find(
            &sp_table->page_locs,
            &search_upl.hash_elem
    );

    ASSERT(found_elem);

    struct user_page_location *upl = hash_entry(
            found_elem,
            struct user_page_location,
            hash_elem
    );

//    printf("updating %i to %i\n", upl->location_type, new_location_type);
    upl->location = new_location;
    upl->location_type = new_location_type;

    rec_lock_release(&sp_table->lock);
}

void sp_destroy(struct sp_table *sp_table, hash_action_func clear_entry) {
    rec_lock_acquire(&sp_table->lock);
    hash_destroy(&sp_table->page_locs, clear_entry);
    rec_lock_release(&sp_table->lock);
}

/*
 * Looks up the given upage in the given sp_table. Returns NULL if it is not
 * there.
 */
struct user_page_location *sp_lookup(struct sp_table *sp_table, void *upage) {
    ASSERT(is_page_aligned(upage));
    struct user_page_location search_upl;
    search_upl.upage = upage;

    rec_lock_acquire(&sp_table->lock);
    struct hash_elem *found_elem = hash_find(
            &sp_table->page_locs,
            &search_upl.hash_elem
    );
    rec_lock_release(&sp_table->lock);

    if (!found_elem) {
        return NULL;
    }

    struct user_page_location *upl = hash_entry(
            found_elem,
            struct user_page_location,
            hash_elem
    );

    return upl;
}


unsigned user_location_hash_func(const struct hash_elem *e, void *aux UNUSED) {
    struct user_page_location *location = hash_entry(
            e,
            struct user_page_location,
            hash_elem
    );
    return (unsigned) location->upage;
}

bool user_location_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    struct user_page_location *l1 = hash_entry(a, struct user_page_location, hash_elem);
    struct user_page_location *l2 = hash_entry(b, struct user_page_location, hash_elem);
    return (unsigned) l1->upage < (unsigned) l2->upage;
}

void user_location_destroy(struct hash_elem *e, void *aux UNUSED) {
    struct user_page_location *upl = hash_entry(e, struct user_page_location, hash_elem);

    if (upl->location_type == EXECUTABLE) {
        free((struct executable_location *) upl->location);
    }

    free(upl);
}


