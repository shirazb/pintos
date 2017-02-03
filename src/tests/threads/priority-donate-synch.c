#include <stdio.h>
#include "threads/init.h"
#include <threads/malloc.h>
#include "tests/threads/tests.h"
#include "threads/synch.h"
#include "threads/thread.h"

static thread_func consumer;
static thread_func producer;

static struct lock lock;
static struct list ints1;
static struct list ints2;
static int int_list_size = 100;
static int num_threads = 100;

struct int_elem {
    int val;
    struct list_elem elem;
};

void
test_priority_donate_synch(void) {
    /* This test does not work with the MLFQS. */
    ASSERT (!thread_mlfqs);

    lock_init(&lock);
    list_init(&ints1);
    list_init(&ints2);

    // Populate ints1
    for (int i = 0; i < int_list_size * num_threads; i++) {
        struct int_elem *number = malloc(sizeof(struct int_elem));
        number->val = i;
        list_push_front(&ints1, &number->elem);
    }

    // Main will create all threads first
    thread_set_priority(PRI_DEFAULT);
    lock_acquire(&lock);

    // Create producers
    for (int i = 0; i < num_threads; i++) {
        thread_create("producer", PRI_DEFAULT + 1 + (i % 3), producer,
                NULL);
    }

    // Run all producers
    lock_release(&lock);

    // Create consumers
    lock_acquire(&lock);
    for (int i = 0; i < num_threads; i++) {
        thread_create("consumer", PRI_DEFAULT + 1 + (i % 3), consumer,
                NULL);
    }

    // Run all consumers
    lock_release(&lock);

    // Print ints1
    puts("ints1 = [");
    struct list_elem *e;
    for (e = list_begin(&ints1); e != list_end(&ints1); e = list_next(e)) {
        int val = list_entry(e, struct int_elem, elem)->val;
        printf("%i, ", val);
    }
    puts("]\n");

    // Print ints2
    puts("ints2 (should be empty) = [");
    struct list_elem *f;
    for (f = list_begin(&ints2); f != list_end(&ints2); f = list_next(f)) {
        int val = list_entry(f, struct int_elem, elem)->val;
        printf("%i, ", val);
    }
    puts("]\n");

    // Free all of ints1 and assert they are correct order
    struct list_elem *g = list_begin(&ints1);
    for (int i = int_list_size * num_threads - 1; i >= 0; i--) {
        struct int_elem *number = list_entry(g, struct int_elem, elem);
        if (number->val != i) {
            printf("ASSERTION FAILED: LIST NOT IN ORDER. Expected: %i. Got: "
                           "%i\n", i, number->val);
        }
        g = list_next(g);
        free(number);
    }
    ASSERT(g == list_end(&ints1));
}

/* Move numbers from ints1 to ints2 */
static void
producer(void *aux UNUSED) {
    for (int i = 0; i < int_list_size; i++) {
        lock_acquire(&lock);
        struct int_elem *number = list_entry(list_pop_front(&ints1),
                                             struct int_elem, elem);
        list_push_front(&ints2, &number->elem);
        lock_release(&lock);
    }
}

/* Move numbers back from ints2 to ints1 */
static void
consumer(void *aux UNUSED) {
    for (int i = 0; i < int_list_size; i++) {
        lock_acquire(&lock);
        struct int_elem *number = list_entry(list_pop_front(&ints2),
                                             struct int_elem, elem);
        list_push_front(&ints1, &number->elem);
        lock_release(&lock);
    }
}

