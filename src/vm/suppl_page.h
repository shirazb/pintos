
#ifndef PINTOS_36_SUPPL_PAGE_H
#define PINTOS_36_SUPPL_PAGE_H

#include <stddef.h>
#include <hash.h>

struct sp_table {
    struct hash pages; // map<page_addr, page_num_entry>
};

struct page_num_entry {
    size_t page_num;
    void *addr;
    struct hash_elem hash_elem;
};

void sp_table_init(struct sp_table *sp_table);

size_t get_page_num(struct sp_table *page_table, void *addr);

#endif //PINTOS_36_SUPPL_PAGE_H
