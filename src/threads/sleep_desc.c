#include "sleep_desc.h"
#include <lib/debug.h>

static void wake_up (struct sleep_desc *desc);
static bool has_overslept (struct sleep_desc *desc, int64_t ticks);

/**
 * Initialises a thread_sleep_desc. Semaphore is initialised with 0. Adds thread
 * to sleeping_threads list.
 */
void
sleep_desc_init (struct sleep_desc *desc, int64_t wake_time, struct list *sleeping_threads)
{
  ASSERT (desc != NULL);

  desc->wake_time = wake_time;
  list_push_back (sleeping_threads, &desc->sleep_elem);
  sema_init(&desc->sema, 0);
}

/**
 * If ticks exceeds the threads wake time, wakes the thread up
 */
void
sleep_desc_wake_if_overslept(struct sleep_desc *desc, int64_t ticks)
{
  if (has_overslept (desc, ticks))
    {
      wake_up (desc);
    }
}

/**
 * Wakes a thread (by upping its semaphore). Only to be called by
 * wake_if_overslept().
 * @param t Thread to wake.
 */
static void
wake_up (struct sleep_desc *desc)
{
  ASSERT (desc != NULL);
  sema_up (&desc->sema);
  list_remove (&desc->sleep_elem);
  desc = NULL;
}

/**
 * has_overslept(t) <-> ticks has now exceeded t->wake_time.
 * @param t Thread whose sleep time is being checked.
 * @return If ticks now exceeds t->wake_time.
 */
static bool
has_overslept (struct sleep_desc *desc, int64_t ticks)
{
  ASSERT (desc != NULL);
  return ticks >= desc->wake_time;
}