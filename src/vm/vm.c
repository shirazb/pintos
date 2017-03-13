#include <threads/palloc.h>
#include <lib/debug.h>
#include <threads/synch.h>
#include <threads/thread.h>
#include <userprog/process.h>
#include <vm/frame.h>
#include <vm/swap.h>
#include <userprog/pagedir.h>
#include <threads/malloc.h>
#include "vm.h"

/* Synchronisation across the entire vm interface. */
static void lock_vm(void);
static void unlock_vm(void);

static void swap_out_frame();

static struct rec_lock vm_lock;

/*
 * Locks the vm.
 */
static void lock_vm(void) {
    rec_lock_acquire(&vm_lock);
}

/*
 * Unlocks the vm.
 */
static void unlock_vm(void) {
    rec_lock_release(&vm_lock);
}
/*
 * Initialises the vm.
 *
 * This includes initialising the vm lock, the swap table, and the frame table.
 */
void vm_init(void) {
    rec_lock_init(&vm_lock);
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
// TODO: Handle PAL_ZERO case
void *vm_alloc_user_page(enum palloc_flags flags, void *upage) {
    // Register a new frame in the frame table and return it.
    struct frame *free_frame = ft_init_new_frame(flags, upage);

    // Frame table was full; perform eviction.
    if (free_frame == NULL) {
        lock_vm();

        swap_out_frame();

        // Try again.
        free_frame = ft_init_new_frame(flags, upage);

        unlock_vm();
        ASSERT(free_frame != NULL);
    }

    // Add this upage -> kpage mapping to the process' supplementary page table.
    sp_add_entry(&process_current()->sp_table, upage, free_frame->kpage, FRAME);

    return free_frame->kpage;
}

void *vm_handle_page_fault(void *upage) {

    // Look up upage in the process' supplementary page table.
    struct sp_table *sp_table = &process_current()->sp_table;
    struct user_page_location *upl = sp_lookup(sp_table, upage);
    if (upl == NULL) {
        process_exit();
        NOT_REACHED();
    }

    // Synchronously make local copies of the location and location type.
    rec_lock_acquire(&sp_table->lock);
    void *location = upl->location;
    enum location_type location_type = upl->location_type;
    rec_lock_release(&sp_table->lock);

    lock_vm();

    // Handle the page fault according to where the page is actually stored.
    void *kpage;
    switch (location_type) {
        case SWAP:
            kpage = vm_alloc_user_page(PAL_USER, upage);
            st_swap_into_kpage((size_t) location, kpage);
            sp_update_entry(sp_table, upage, kpage, FRAME);
            break;
        case ZERO:
            //TODO
            kpage = (void *) -1;
            break;
        case FRAME:
            PANIC("vm_handle_page_fault(): Page faulted when sp table says "
                          "upage maps to a frame.");
        default:
            PANIC("vm_handle_page_fault(): User page location has unknown "
                          "location_type: %i", location_type);
    }

    unlock_vm();

    return kpage;
}

/*
 * Swaps out a frame from physical memory to the swap space.
 *
 * Removes the entry from the frame table, updates the thread that
 * owns the evicted frame's supplementary page table, and updates its page
 * table.
 */
static void swap_out_frame() {
    struct frame *evicted_frame = ft_evict_frame();
    ASSERT(evicted_frame != NULL);

    size_t swap_slot = st_swap_out_kpage(
            evicted_frame->thread_used_by,
            evicted_frame->upage,
            evicted_frame->kpage
    );

    struct thread *thread_of_evicted_frame = evicted_frame->thread_used_by;

    sp_update_entry(
                &thread_of_evicted_frame->process->sp_table,
                evicted_frame->upage,
                (void *) swap_slot,
                SWAP
    );

    pagedir_clear_page(
                thread_of_evicted_frame->pagedir,
                evicted_frame->upage
    );

    free(evicted_frame);
}

void vm_free_user_page(void *kpage) {
    struct frame *frame = ft_lookup(kpage);
    struct sp_table *sp_table = &frame->thread_used_by->process->sp_table;

    lock_vm();
    sp_remove_entry(sp_table, frame->upage);
    ft_destroy(frame);
    unlock_vm();
}

