#include <threads/malloc.h>
#include <userprog/process.h>

static hash_hash_func user_location_hash_func;
static hash_less_func user_location_less_func;

unsigned int hash_location(const struct user_page_location *location);

void sp_table_init(struct sp_table *sp_table) {
    lock_init(&sp_table->lock);
    hash_init(&sp_table->page_locs, user_location_hash_func, user_location_less_func, NULL);
}

void sp_table_destroy(struct sp_table *sp_table) {

}

void sp_add_frame(struct sp_table *sp_table, void *kpage) {
    struct user_page_location *location = malloc(sizeof(struct user_page_location));
    if (!location) {
        process_exit();
        NOT_REACHED();
    }

    location->location_type = FRAME;
    location->location = kpage;

    lock_acquire(&sp_table->lock);
    hash_insert(&sp_table->page_locs, &location->hash_elem);
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
