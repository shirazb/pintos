
#ifndef PINTOS_36_SUPPL_PAGE_H
#define PINTOS_36_SUPPL_PAGE_H

#include <stddef.h>
#include <hash.h>

struct sp_table {
    struct lock lock;
    struct hash page_locs; // map<*upage, *user_page_location>
};

enum location_type {
    FRAME,
    SWAP,
    ZERO
};

struct user_page_location {
    void *upage;
    void *location;
    enum location_type location_type;
    struct hash_elem hash_elem;
};

void sp_table_init(struct sp_table *sp_table);
void sp_table_destroy(struct sp_table *sp_table);
void sp_add_entry(struct sp_table *sp_table, void *upage, void *location, enum location_type location_type);
void sp_remove_entry(struct sp_table *sp_table, void *upage);
void sp_update_entry(struct sp_table *sp_table, void *upage, void *new_location, enum location_type new_location_type);

#endif //PINTOS_36_SUPPL_PAGE_H
