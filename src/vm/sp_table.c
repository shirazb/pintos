#include <threads/malloc.h>
#include <userprog/process.h>

static hash_hash_func user_location_hash_func;
static hash_less_func user_location_less_func;
static hash_action_func user_location_destroy;

unsigned int hash_location(const struct user_page_location *location);

void sp_table_init(struct sp_table *sp_table) {
    enum intr_level old_level = intr_disable();
    lock_init(&sp_table->lock);
    hash_init(&sp_table->page_locs, user_location_hash_func, user_location_less_func, NULL);
    intr_set_level(old_level);
}

void sp_table_destroy(struct sp_table *sp_table) {
    hash_destroy(&sp_table->page_locs, user_location_destroy);
}

void sp_add_entry(struct sp_table *sp_table, void *kpage, enum location_type location_type) {
    struct user_page_location *location = malloc(sizeof(struct user_page_location));
    if (!location) {
        process_exit();
        NOT_REACHED();
    }

    location->location_type = location_type;
    location->location = kpage;

    lock_acquire(&sp_table->lock);
    hash_insert(&sp_table->page_locs, &location->hash_elem);
    lock_release(&sp_table->lock);
}

void sp_remove_entry(struct sp_table *sp_table, void *upage, enum location_type location) {
    struct user_page_location search_upl;
    search_upl.location = upage;
    search_upl.location_type = location;

    lock_acquire(&sp_table->lock);
    struct hash_elem *e = hash_delete(&sp_table->page_locs, &search_upl.hash_elem);
    lock_release(&sp_table->lock);
    ASSERT(e);

    user_location_destroy(e, NULL);
}

void sp_update_entry(
        struct sp_table *sp_table,
        void *old_location,
        enum location_type old_location_type,
        void *new_location,
        enum location_type new_location_type
) {
    struct user_page_location search_upl;
    search_upl.location = old_location;
    search_upl.location_type = old_location_type;

    lock_acquire(&sp_table->lock);
    struct hash_elem *found_elem = hash_find(&sp_table->page_locs,
                                             &search_upl.hash_elem);
    ASSERT(found_elem);

    struct user_page_location *upl = hash_entry(
            found_elem,
            struct user_page_location,
            hash_elem
    );

    upl->location = new_location;
    upl->location_type = new_location_type;

    lock_release(&sp_table->lock);
}


unsigned int hash_location(const struct user_page_location *location) {
    return (unsigned) location->location * 31 + location->location_type * 7;
}

unsigned user_location_hash_func(const struct hash_elem *e, void *aux UNUSED) {
    struct user_page_location *location = hash_entry(e, struct user_page_location, hash_elem);
    return hash_location(location);
}

bool user_location_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    struct user_page_location *l1 = hash_entry(a, struct user_page_location, hash_elem);
    struct user_page_location *l2 = hash_entry(b, struct user_page_location, hash_elem);
    return hash_location(l1) < hash_location(l2);
}

void user_location_destroy(struct hash_elem *e, void *aux UNUSED) {
    struct user_page_location *location = hash_entry(e, struct user_page_location, hash_elem);
    free(location);
}
