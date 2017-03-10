
#include <vm/suppl_page.h>
#include <lib/debug.h>


void sp_table_init(struct sp_table *sp_table) {
    hash_init(&sp_table->pages, NULL, NULL, NULL);
}

size_t get_page_num(struct sp_table *page_table, void *addr) {

    // pages.get(addr)
    struct page_num_entry search_entry;
    search_entry.addr = addr;
    struct hash_elem *e = hash_find(&page_table->pages, &search_entry.hash_elem);

    // TODO: check that this doesn't happen
    if (!e) {
        NOT_REACHED();
    }

    struct page_num_entry *entry = hash_entry(e, struct page_num_entry, hash_elem);

    return entry->page_num;
}


