#ifndef PINTOS_TASK0_SB4515_SLEEP_DESC_H
#define PINTOS_TASK0_SB4515_SLEEP_DESC_H

#include <list.h>
#include <stdint.h>
#include <threads/synch.h>
#include <threads/interrupt.h>

/* Contains info for implementing the sleeping of threads without busy waiting,
   used in timer_sleep() and timer_interrupt().

   Factoring this out allows it to be kept in the sleep timer's stack frame.

   Require access to the semaphore to sleep / wake the thread.
   Require access to wake_time to know when to wake the thread.
   Require access to the list_elem so thread.c can maintain a list of sleeping
     threads.
*/
struct sleep_desc
{
    struct semaphore sema;           /* Used to sleep the thread */
    int64_t wake_time;               /* Scheduled waking up time */
    struct list_elem sleep_elem;     /* List element for sleeping_threads */
};

void sleep_desc_init (struct sleep_desc *desc, int64_t wake_time, struct list *sleeping_threads);
void sleep_desc_wake_if_overslept (struct sleep_desc *desc, int64_t ticks);

#endif //PINTOS_TASK0_SB4515_SLEEP_DESC_H
