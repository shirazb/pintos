
#ifndef PINTOS_36_SUPPL_PAGE_H
#define PINTOS_36_SUPPL_PAGE_H

#include <stddef.h>
#include <hash.h>

struct sp_table {
    struct rec_lock lock;
    struct hash page_locs; // map<*upage, *user_page_location>
};

enum location_type {
    FRAME,
    SWAP,
    ZERO,
    EXECUTABLE
};

struct user_page_location {
    void *upage;
    void *location;
    enum location_type location_type;
    struct hash_elem hash_elem;
};

struct executable_location {
    struct file *file;
    size_t page_read_bytes;
};

void sp_table_init(struct sp_table *sp_table);
void sp_clear_table(struct sp_table *sp_table, hash_action_func clear_entry);
void sp_add_entry(struct sp_table *sp_table, void *upage, void *location, enum location_type location_type);
void sp_destroy(struct sp_table *sp_table);
void sp_remove_entry(struct sp_table *sp_table, void *upage);
void sp_update_entry(struct sp_table *sp_table, void *upage, void *new_location, enum location_type new_location_type);
struct user_page_location * sp_lookup(struct sp_table *sp_table, void *upage);

#endif //PINTOS_36_SUPPL_PAGE_H
