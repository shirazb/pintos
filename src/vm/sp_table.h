
#ifndef PINTOS_36_SUPPL_PAGE_H
#define PINTOS_36_SUPPL_PAGE_H

#include <stddef.h>
#include <hash.h>

struct sp_table {
    struct hash page_locs; // map<*u_page, *user_page_location>
};

struct user_page_location {
    void *location;
    enum location_type location_type;
    struct hash_elem hash_elem;
};

enum location_type {
    FRAME,
    SWAP,
    ZERO
};

void sp_table_init(struct sp_table *sp_table);

#endif //PINTOS_36_SUPPL_PAGE_H
