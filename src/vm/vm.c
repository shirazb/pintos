#include <threads/palloc.h>
#include <lib/debug.h>
#include <threads/synch.h>
#include <threads/thread.h>
#include <userprog/process.h>
#include <vm/frame.h>
#include <vm/swap.h>
#include "vm.h"

/* Synchronisation across the entire vm interface. */
static void lock_vm(void);
static void unlock_vm(void);

static struct lock vm_lock;

/*
 * Locks the vm.
 */
static void lock_vm(void) {
    lock_acquire(&vm_lock);
}

/*
 * Unlocks the vm.
 */
static void unlock_vm(void) {
    lock_release(&vm_lock);
}
/*
 * Initialises the vm.
 *
 * This includes initialising the vm lock, the swap table, and the frame table.
 */
void vm_init(void) {
    lock_init(&vm_lock);
    ft_init();
    st_init();
}

/*
 * Allocates a new user page in our memory model, performing a swap if
 * necessary. This does not affect the physical page table of the
 * process that requested the page.
 *
 * Returns the kernel page that the user page was mapped to.
 */
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

    sp_add_entry(&process_current()->sp_table, free_frame->kpage, FRAME);

    return free_frame->kpage;
}

void vm_free_user_page(void *kpage) {
    struct frame *frame = ft_lookup(kpage);
    struct sp_table *sp_table = &frame->thread_used_by->process->sp_table;

    lock_vm();
    sp_remove_entry(sp_table, frame->upage, FRAME);
    ft_remove(frame);
    unlock_vm();
}
