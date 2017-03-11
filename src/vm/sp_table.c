
#include <threads/malloc.h>
#include <userprog/process.h>

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
