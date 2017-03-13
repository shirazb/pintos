#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/* A counting semaphore. */
struct semaphore {
    unsigned value;             /* Current value. */
    struct list waiters;        /* List of waiting threads. */
};

void sema_init(struct semaphore *, unsigned value);

void sema_down(struct semaphore *);

bool sema_try_down(struct semaphore *);

void sema_up(struct semaphore *);

void sema_self_test(void);

/* Lock. */
struct lock {
    struct thread *holder;      /* Thread holding lock (for debugging). */
    struct semaphore semaphore; /* Binary semaphore controlling access. */
};

void lock_init(struct lock *);

void lock_acquire(struct lock *);

bool lock_try_acquire(struct lock *);

void lock_release(struct lock *);

bool lock_held_by_current_thread(const struct lock *);

/*
 * Readers-writer lock that prevents the readers from starving the writers and vice versa.
 * Note: a writer can still starve if the writers aren't woken up in FIFO.
 */
struct read_write_lock {
    unsigned int num_readers;
    struct lock num_readers_access;
    struct lock wait_for_service;
    struct semaphore resource_access;
};

void rw_lock_init(struct read_write_lock *rw_lock);

void r_lock_acquire(struct read_write_lock *rw_lock);

void r_lock_release(struct read_write_lock *rw_lock);

void w_lock_acquire(struct read_write_lock *rw_lock);

void w_lock_release(struct read_write_lock *rw_lock);

/*
 * recursive lock for vm.
 */

struct rec_lock {
    unsigned num_acquires;
    struct lock lock;
};

void rec_lock_init(struct rec_lock *rec_lock);
void rec_lock_acquire(struct rec_lock *rec_lock);
void rec_lock_release(struct rec_lock *rec_lock);

/* Condition variable. */
struct condition {
    struct list waiters;        /* List of waiting semaphore_elems. */
};

void cond_init(struct condition *);

void cond_wait(struct condition *, struct lock *);

void cond_signal(struct condition *, struct lock *);

void cond_broadcast(struct condition *, struct lock *);

/* Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile ("" : : : "memory")

#endif /* threads/synch.h */
