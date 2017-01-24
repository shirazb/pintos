#ifndef PINTOS_36_THREAD_QUEUE_H
#define PINTOS_36_THREAD_QUEUE_H

#include <list.h>
#include <threads/synch.h>
#include <stdbool.h>

struct ordered_list {
    struct list list;
    list_less_func *less; // Should the void *aux param to less be a parameter of ordered_list (in the struct) or passed in to each function that requires use of the less func?
    struct lock lock;
};

void ordered_list_init(struct ordered_list *, list_less_func *);

void ordered_list_resort(struct ordered_list *, struct list_elem *, void *aux);

void ordered_list_insert(struct ordered_list *, struct list_elem *, void * aux);
struct list_elem *ordered_list_pop_front(struct ordered_list *);

bool ordered_list_empty(struct ordered_list *);

#endif //PINTOS_36_THREAD_QUEUE_H
