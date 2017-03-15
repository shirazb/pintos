#include <threads/palloc.h>
#include <lib/debug.h>
#include <threads/synch.h>
#include <threads/thread.h>
#include <userprog/process.h>
#include <vm/frame.h>
#include <vm/swap.h>
#include <userprog/pagedir.h>
#include <threads/malloc.h>
#include <threads/vaddr.h>
#include <filesys/file.h>
#include <string.h>
#include "vm.h"

/* Synchronisation across the entire vm interface. */
static void lock_vm(void);
static void unlock_vm(void);

static void swap_out_frame(void);

static void * vm_grow_stack(void *upage);

static void *load_exec_page(void *upage);

static struct rec_lock vm_lock;

static hash_action_func clear_entry;

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
    ASSERT(is_page_aligned(upage));
    
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

void *vm_handle_page_fault(void *uaddr, void *esp) {

    void *kpage;
    void *upage = pg_round_down(uaddr);

    unsigned long offset = esp - uaddr;
    bool grow_the_stack = (esp <= uaddr || offset == 4 || offset == 32) &&
            (PHYS_BASE - MAX_STACK_SIZE <= uaddr && PHYS_BASE > uaddr);
    if (grow_the_stack) {
        return vm_grow_stack(upage);
    }

    // Look up upage in the process' supplementary page table.
    struct sp_table *sp_table = &process_current()->sp_table;
    struct user_page_location *upl = sp_lookup(sp_table, upage);
    if (upl == NULL) {
        return NULL;
    }

    // Synchronously make local copies of the location and location type.
    rec_lock_acquire(&sp_table->lock);
    enum location_type location_type = upl->location_type;
    void *location = upl->location;
    rec_lock_release(&sp_table->lock);

    bool writeable = true;

    lock_vm();

    // Handle the page fault according to where the page is actually stored.
    switch (location_type) {
    case SWAP:
        kpage = vm_alloc_user_page(PAL_USER, upage);
        st_swap_into_kpage((size_t) location, kpage);
        sp_update_entry(sp_table, upage, kpage, FRAME);
        break;
    case ZERO:
        kpage = vm_alloc_user_page(PAL_USER | PAL_ZERO, upage);
        break;
    case EXECUTABLE:
        kpage = load_exec_page(upage);
        // FIXME: Why shouldn't this be true?
        writeable = true;
        break;
    case FRAME:
        PANIC("vm_handle_page_fault(): Page faulted when sp table says "
                      "upage maps to a frame.");
    default:
        PANIC("vm_handle_page_fault(): User page location has unknown "
                      "location_type: %i", location_type);
    }

    unlock_vm();
    bool page_was_set = pagedir_set_page(thread_current()->pagedir, upage, kpage, writeable);
    ASSERT(page_was_set);
    return kpage;
}

static void *load_exec_page(void *upage) {
    ASSERT(is_page_aligned(upage));
    struct user_page_location *upl = sp_lookup(
            &process_current()->sp_table,
            upage
    );
    ASSERT(upl->location_type == EXECUTABLE);


    struct executable_location *exec_loc = (struct executable_location *)
            upl->location;

    // Remove upage -> Filesys mapping in sp table.
    sp_remove_entry(&process_current()->sp_table, upage);

    off_t page_read_bytes = (off_t) exec_loc->page_read_bytes;
    size_t page_zero_bytes = (size_t) (PGSIZE - page_read_bytes);

    // Allocate a new page (includes adding the upage -> frame mapping in sp
    // table).
    void *kpage = vm_alloc_user_page(PAL_USER, upage);

    // Read page_read_bytes bytes of the file into the kpage.
    off_t bytes_written = file_read_at(exec_loc->file, kpage, page_read_bytes, exec_loc->start_pos);

    // Fail if error
    bool read_failed = bytes_written != (int) page_read_bytes;
    bool page_already_taken =
            pagedir_get_page(thread_current()->pagedir, upage) != NULL;

    if (read_failed || page_already_taken) {
        vm_free_user_page(kpage);
        process_exit();
        NOT_REACHED();
    }

    // Zero out the rest of the page (that was no written to).
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    return kpage;
}

/*
 * Swaps out a frame from physical memory to the swap space.
 *
 * Removes the entry from the frame table, updates the thread that
 * owns the evicted frame's supplementary page table, and updates its page
 * table.
 */
static void swap_out_frame(void) {
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

void *vm_grow_stack(void *upage) {
    ASSERT(is_page_aligned(upage));
    void *kpage = vm_alloc_user_page(PAL_USER | PAL_ZERO, upage);
    pagedir_set_page(thread_current()->pagedir, upage, kpage, true);
    return kpage;
}

void vm_free_user_page(void *kpage) {
    struct frame *frame = ft_lookup(kpage);
    struct sp_table *sp_table = &frame->thread_used_by->process->sp_table;

    lock_vm();
    sp_remove_entry(sp_table, frame->upage);
    ft_destroy(frame);
    unlock_vm();
}

void vm_reclaim_pages(void) {
    sp_clear_table(&process_current()->sp_table, clear_entry);
}

void clear_entry(struct hash_elem *e, void *aux UNUSED) {
    struct user_page_location *location = hash_entry(e, struct user_page_location, hash_elem);

    switch (location->location_type) {
    case FRAME:
        break;
    case SWAP:
        st_free_swap_entry((size_t) location->location);
    case EXECUTABLE:
    case ZERO:
    default:
        sp_remove_entry(&process_current()->sp_table, location->upage);
        break;
    }
}

