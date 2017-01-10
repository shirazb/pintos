#include "sleep_desc.h"
#include <lib/debug.h>

static void wake_up (struct sleep_desc *desc);
static bool has_overslept (struct sleep_desc *desc, int64_t ticks);
static list_less_func order_by_wake_time;

/**
 * Initialises a thread_sleep_desc. Semaphore is initialised with 0. Adds thread
 * to sleeping_threads list.
 */
void
sleep_desc_init (struct sleep_desc *desc, int64_t wake_time, struct list *sleeping_threads)
{
  ASSERT (desc != NULL);

  desc->wake_time = wake_time;
  sema_init(&desc->sema, 0);

  enum intr_level old_level = intr_set_level(INTR_OFF);
  list_insert_ordered (sleeping_threads, &desc->sleep_elem, order_by_wake_time, NULL);
  intr_set_level(old_level);
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

/**
 * Orders two sleep_descs by their wait time, first to wake up first.
 */
static bool
order_by_wake_time (const struct list_elem *a,
                    const struct list_elem *b,
                    void *aux UNUSED)
{
  struct sleep_desc *s1 = list_entry(a, struct sleep_desc, sleep_elem);
  struct sleep_desc *s2 = list_entry(b, struct sleep_desc, sleep_elem);

  ASSERT (s1 != NULL && s2 != NULL);

  return s1->wake_time <= s2->wake_time;
}