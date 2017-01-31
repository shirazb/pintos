#include <lib/debug.h>
#include <stdio.h>
#include "ordered_list.h"


void
ordered_list_init(struct ordered_list *ol, list_less_func *less, void *aux) {
    ASSERT(ol != NULL);
    ASSERT(less != NULL);

    list_init(&ol->list);
    ol->less = less;
    ol->aux = aux;
}

/**
 * Given an ordered_list whose single list_elem has become out of order,
 * puts it back in order by removal then ordered insertion.
 */
// TODO: WRITE COMMENT HERE EXPLAINING WHY REMOVE/INSERT IS FASTER THAN SORT
void
ordered_list_reinsert(struct ordered_list *ol, struct list_elem *elem) {
    ASSERT(ol != NULL);

    struct list_elem *removed = list_remove(elem);
    ASSERT(removed != NULL);
    list_insert_ordered(&ol->list, elem, ol->less, ol->aux);
}

void
ordered_list_resort(struct ordered_list *ol) {
    ASSERT(ol != NULL);
    list_sort(&ol->list, ol->less, NULL);
}

void
ordered_list_insert(struct ordered_list *ol, struct list_elem *elem) {
    ASSERT(ol != NULL);
    ol->list.size++;
    list_insert_ordered(&ol->list, elem, ol->less, ol->aux);
}

struct list_elem *
ordered_list_front(struct ordered_list *ol) {
    ASSERT(ol != NULL);
    return list_front(&ol->list);
}

struct list_elem *
ordered_list_pop_front(struct ordered_list *ol) {
    ASSERT(ol != NULL);
    ol->list.size--;
    return list_pop_front(&ol->list);
}

bool ordered_list_empty(struct ordered_list *ol) {
    ASSERT(ol != NULL);
    return list_empty(&ol->list);
}


int ordered_list_size(struct ordered_list *ol) {
    if (ol->list.size != 0) {
        printf("yaya");
    }
    return ol->list.size;
}
