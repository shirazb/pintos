#ifndef PINTOS_36_THREAD_QUEUE_H
#define PINTOS_36_THREAD_QUEUE_H

#include <list.h>
#include <stdbool.h>
#include <threads/synch.h>

struct ordered_list {
    struct list list;
    list_less_func *less;
    void *aux;
    struct lock lock;
};

void ordered_list_init(struct ordered_list *, list_less_func *, void *aux);

void ordered_list_resort(struct ordered_list *, struct list_elem *);

void ordered_list_insert(struct ordered_list *, struct list_elem *);
struct list_elem *ordered_list_pop_front(struct ordered_list *);

bool ordered_list_empty(struct ordered_list *);

#endif //PINTOS_36_THREAD_QUEUE_H
