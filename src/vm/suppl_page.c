
#include <vm/suppl_page.h>
#include <lib/debug.h>

static hash_hash_func page_num_hash_func;
static hash_less_func page_num_less_func;

void sp_table_init(struct sp_table *sp_table) {
    hash_init(&sp_table->pages, page_num_hash_func, page_num_less_func, NULL);
}

void sp_table_destroy(struct sp_table *sp_table) {
    //TODO
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

// page num hashing function using the page address
unsigned page_num_hash_func(const struct hash_elem *e, void *aux UNUSED) {

    struct page_num_entry *entry = hash_entry(e, struct page_num_entry, hash_elem);
    unsigned page_addr = (unsigned) entry->addr;

    return page_addr * 31;
}

bool page_num_less_func(const struct hash_elem *a,
                        const struct hash_elem *b,
                        void *aux UNUSED) {

    struct page_num_entry *e1 = hash_entry(a, struct page_num_entry, hash_elem);
    struct page_num_entry *e2 = hash_entry(b, struct page_num_entry, hash_elem);

    return e1->addr < e2->addr;
}
