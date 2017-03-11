
#include <threads/palloc.h>
#include <lib/debug.h>
#include <threads/synch.h>
#include <threads/thread.h>
#include <userprog/process.h>
#include "frame.h"

static void lock_vm(void);
static void unlock_vm(void);







static struct lock vm_lock;

static void lock_vm(void) {
    lock_acquire(&vm_lock);
}
static void unlock_vm(void) {
    lock_release(&vm_lock);
}

// TODO: init in init.c
void vm_init(void) {
    lock_init(&vm_lock);
}

// TODO: synchronise
void *vm_alloc_user_page(enum palloc_flags flags, void *upage) {
    struct frame *free_frame = ft_init_new_frame(flags, upage);

    if (free_frame == NULL) {
        lock_vm();
        struct frame *evicted_frame = ft_evict_frame();
        // TODO: add to swap space

        free_frame = ft_init_new_frame(flags, upage);
        unlock_vm();

        ASSERT(free_frame != NULL);
    }

    sp_add_frame(&process_current()->sp_table, free_frame->kpage);

    return free_frame->kpage;
}
