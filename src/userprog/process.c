#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include <threads/malloc.h>
#include <vm/vm.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/vaddr.h"

#define MAX_ARG_NUM 35

// The PID of the kernel thread that acts as a process in order to run the
// test. This should be an otherwise totally unused PID.
#define TEST_PROC_PID -2
#define TEST_PROC_NAME "main"

static thread_func start_process NO_RETURN;

static int parse_args(char *file_name, char **argv);

static void init_process(struct process *parent,
                         char *file_name);
static void destroy_process(struct process *p);

static bool load(const char *cmdline, void (**eip)(void), void **esp);

static hash_hash_func open_file_hash;
static hash_less_func open_file_less;

static void notify_child_of_exit(struct process *p);

static struct start_proc_info {
    char *fn_copy;
    struct process *parent;
    struct semaphore child_is_set_up;
};

/*
 * User program threads have the "main" kernel thread execute and wait on the
 * user program. In order to allow a kernel thread to perform these tasks, we
 * give it the minimum process information required.
 */
void
setup_test_process(void) {
    struct thread *cur = thread_current();
    ASSERT(strcmp(cur->name, TEST_PROC_NAME) == 0);
    init_process(NULL, "main");
}

/*
 * Cleans up process resources of the test process.
 */
void
tear_down_test_process(void) {
    ASSERT(strcmp(thread_current()->name, TEST_PROC_NAME) == 0);

    destroy_process(process_current());
}

/*
 * Initialises the process struct of a thread.
 */
static void
init_process(struct process *parent, char *file_name) {
    ASSERT (file_name != NULL);

    struct process *p = malloc (sizeof (struct process));

    if (p == NULL) {
        thread_exit();
        NOT_REACHED();
    }

    enum intr_level old_level = intr_disable();


    // Init the process struct.
    lock_init(&p->process_lock);
    p->exit_status = EXIT_FAILURE;
    hash_init(&p->open_files, open_file_hash, open_file_less, NULL);
    sema_init(&p->wait_till_death, 0);
    p->parent_is_alive = true;
    list_init(&p->children);
    p->executable_name = file_name;
    p->next_fd = LOWEST_FILE_FD;
    p->loaded_correctly = false;
    sema_init(&p->has_loaded, 0);
    sp_table_init(&p->sp_table);

    // Will be set in load.
    p->executable = NULL;

    // If there is no parent, this is the kernel test thread.
    if (parent == NULL) {
        ASSERT(strcmp(thread_current()->name, TEST_PROC_NAME) == 0);
        p->pid = TEST_PROC_PID;
    } else {
        // Makes current process a child of the parent
        list_push_front(&parent->children, &p->child_proc_elem);
        p->pid = thread_current()->tid;
    };

    thread_current()->process = p;

    intr_set_level(old_level);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute(const char *file_name) {
    char *fn_copy;
    tid_t tid;

    /* Make a copy of FILE_NAME.
       Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL) {
        return TID_ERROR;
    }
    strlcpy(fn_copy, file_name, PGSIZE);

    // Make process info
    struct start_proc_info proc_info;

    proc_info.fn_copy = fn_copy;
    proc_info.parent = process_current();
    sema_init(&proc_info.child_is_set_up, 0);

    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create(file_name, PRI_DEFAULT, start_process, &proc_info);

    if (tid == TID_ERROR) {
        palloc_free_page(fn_copy);
    } else {
        sema_down(&proc_info.child_is_set_up);
    }

    return tid;
}

/*
 * Returns the file from the file descriptor that the process has opened.
 * Returns NULL if process does not have the given fd.
 */
struct file *
process_get_open_file(int fd) {
    // Get the open file
    struct open_file_s search_fd;
    search_fd.fd = fd;

    struct thread *curr = thread_current();

    lock_acquire(&curr->process->process_lock);
    struct hash open_files = curr->process->open_files;
    lock_release(&curr->process->process_lock);

    struct open_file_s *found_fd = hash_entry(
            hash_find(
                    &open_files, &search_fd.fd_elem
            ),
            struct open_file_s,
            fd_elem
    );

    return found_fd == NULL ? NULL : found_fd->file;
}

/*
 * Get the open_file struct of the process from its fd.
 */
struct open_file_s *
process_get_open_file_struct(int fd) {
    // fd 0 and 1 are reserved for stout and stderr respectively.
    if (fd < LOWEST_FILE_FD) {
        return NULL;
    }

    struct process *cur = process_current();

    // Get the corresponding open file from the hash map.
    struct open_file_s search_open_file;
    search_open_file.fd = fd;

    lock_acquire(&cur->process_lock);
    struct hash_elem *found_file_elem = hash_find(
            &cur->open_files,
            &search_open_file.fd_elem
    );
    lock_release(&cur->process_lock);

    // File not found, return NULL.
    if (found_file_elem == NULL) {
        return NULL;
    }

    // Else, return the file.
    struct open_file_s *open_file = hash_entry(
            found_file_elem,
            struct open_file_s,
            fd_elem
    );

    return open_file;
}

/* A thread function that loads a user process and starts it
  running. */
static void
start_process(void *start_proc_info) {
    // Read parameters
    struct start_proc_info *start_info = (struct start_proc_info *) start_proc_info;
    struct process *parent = start_info->parent;
    char *file_name = start_info->fn_copy;


    /* Start setting up the stack. */

    struct intr_frame if_;

    /* Initialize interrupt frame and load executable. */
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;

    //Parse file_name to obtain argv, the list of arguments.
    char *argv[MAX_ARG_NUM];
    int argc = parse_args(file_name, argv);

    //Setting file name to be the first arg in parsed list of args
    file_name = argv[0];

    // Malloc and initialise the process struct.
    init_process(parent, file_name);
    sema_up(&start_info->child_is_set_up);
    struct process *curr_proc = process_current();

    // Leave thread if loading of executable fails
    curr_proc->loaded_correctly = load(file_name, &if_.eip, &if_.esp);
    sema_up(&curr_proc->has_loaded);

    if (!curr_proc->loaded_correctly) {
        curr_proc->exit_status = EXIT_FAILURE;
        process_exit();
        NOT_REACHED();
    }

    //Setting up the stack for user programs

    //Pushing arguments onto stack in reverse order
    for (int i = argc - 1; i >= 0; i--) {

        //Obtaining arg and its size in reverse order
        char *arg = argv[i];
        size_t arg_len = strlen(arg) + 1;

        //Making space for arg, copying it into stack at position esp
        // and point argv list elem to it
        if_.esp -= arg_len;
        strlcpy(if_.esp, arg, arg_len);
        argv[i] = if_.esp;
    }

    //Rounding the stack pointer down to a multiple of 4 as word-aligned
    // access is faster
    if_.esp -= (unsigned) if_.esp % 4;

    //Push a null pointer sentinel for alignment
    if_.esp -= sizeof(uint8_t *);
    *((uint8_t *) if_.esp) = (uint8_t) 0;

    //Push pointers to the arguments in reverse
    for (int i = argc - 1; i >= 0; i--) {
        if_.esp -= sizeof(char *);
        *(char **) if_.esp = argv[i];
    }

    //Push a pointer to the first arg
    if_.esp -= sizeof(char **);
    *((char **) if_.esp) = if_.esp + sizeof(char **);

    //Push the argc (number of arguments)
    if_.esp -= sizeof(int);
    *((int *) if_.esp) = argc;

    //Make space for a fake return address. Setting it is unnecessary
    // as it is never popped from the stack. Just needs the same structure
    if_.esp -= sizeof(void (**)(void));
    *((void (**)(void)) if_.esp) = NULL;


    /* Start the user process by simulating a return from an
       interrupt, implemented by intr_exit (in
       threads/intr-stubs.S).  Because intr_exit takes all of its
       arguments on the stack in the form of a `struct intr_frame',
       we just point the stack pointer (%esp) to our stack frame
       and jump to it. */
    asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
    NOT_REACHED ();
}


static int
parse_args(char *file_name, char **argv) {

    ASSERT(file_name != NULL);
    ASSERT(argv != NULL);

    char *arg;
    char *save_ptr;

    int argc = 0;
    int total_arg_bytes = 0;

    for (arg = strtok_r(file_name, " ", &save_ptr);
         arg != NULL;
         argc++, arg = strtok_r(NULL, " ", &save_ptr)) {

        int arg_len = (int) strlen(arg);

        //Return immediately if size exceeds page size
        if (PGSIZE < arg_len + total_arg_bytes) {
            return argc;
        }

        //Store each arg in input array
        argv[argc] = arg;
        total_arg_bytes += arg_len;

    }

    //Exit thread upon error in arg parsing
    if (argc < 0) {
        thread_exit();
    }

    ASSERT(argv[0] != NULL);
    ASSERT(argc >= 1);
    return argc;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait(tid_t child_tid) {
    struct process *p = process_current();
    struct process *child_proc = child_process_from_pid(child_tid, p);

    // If child not found or already waited on or was killed by kernel, fail.
    if (child_proc == NULL) {
        return EXIT_FAILURE;
    }

    // Wait for child process to finish then get its exit status.
    sema_down(&child_proc->wait_till_death);
    int exit_status = child_proc->exit_status;

    // Free the child proc, it is no longer needed.
    destroy_process(child_proc);

    return exit_status;
}

/*
 * Destroys a process struct -- frees its members on the heap then frees itself.
 */
void
open_files_destroy_func (struct hash_elem *e, void *aux UNUSED) {
    struct open_file_s *open_file = hash_entry (e,
                                                struct open_file_s,
                                                fd_elem);

    ASSERT (open_file->file != NULL);

    // Close the file descriptor for the open file.
    file_close (open_file->file);
    free (open_file);
}

static void
destroy_process(struct process *p) {
    ASSERT(p != NULL);
    enum intr_level old_level = intr_disable();

    hash_destroy(&p->open_files, &open_files_destroy_func);
    if (p->pid != TEST_PROC_PID) {
        list_remove (&p->child_proc_elem);
    }

    free(p);

    intr_set_level(old_level);
}

/* Free the current process's resources. */
void
process_exit(void) {
    struct thread *curr = thread_current();
    uint32_t *pd;

    /* Destroy the current process's page directory and switch back
       to the kernel-only page directory. */
    pd = curr->pagedir;
    if (pd != NULL) {
        /* Correct ordering here is crucial.  We must set
           curr->pagedir to NULL before switching page directories,
           so that a timer interrupt can't switch back to the
           process page directory.  We must activate the base page
           directory before destroying the process's page
           directory, or our active page directory will be one
           that's been freed (and cleared). */
        curr->pagedir = NULL;
        pagedir_activate (NULL);
        pagedir_destroy (pd);
        vm_reclaim_pages();
    }

    struct process *proc_curr = process_current();

    enum intr_level old_level = intr_disable();

    struct process *child_proc = NULL;
    for (struct list_elem *e = list_begin (&proc_curr->children);
         e != list_end (&proc_curr->children);
         e = list_next (e))
    {
        child_proc = list_entry (e, struct process, child_proc_elem);
        notify_child_of_exit (child_proc);
    }


    // Print exiting message
    printf("%s: exit(%i)\n", proc_curr->executable_name, proc_curr->exit_status);
    palloc_free_page(proc_curr->executable_name);

    // Close the executable file only now that execution finished and allow
    // writes to it.
    if (proc_curr->loaded_correctly) {
        file_allow_write (proc_curr->executable);
        file_close (proc_curr->executable);
    }

    // If parent is dead, free this process' resources as noone needs them now.
    sema_up(&proc_curr->wait_till_death);
    if (!proc_curr->parent_is_alive) {
        destroy_process (proc_curr);
    }

    intr_set_level (old_level);

    thread_exit ();
    NOT_REACHED ();
}

/*
 * Returns the currently running process. Fails if current thread is not a
 * process.
 */
struct process *
process_current(void) {
    struct process *curr_proc = thread_current()->process;
    ASSERT(curr_proc != NULL);
    return curr_proc;
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate(void) {
    struct thread *t = thread_current();

    /* Activate thread's page tables. */
    pagedir_activate(t->pagedir);

    /* Set thread's kernel stack for use in processing
       interrupts. */
    tss_update();
}

/*
 * Tells the child that its parent is dead. Intended only to be called by
 * process_exit().
 */
static void
notify_child_of_exit(struct process *p) {
    ASSERT(p != NULL);
    ASSERT(intr_get_level() == INTR_OFF);

    p->parent_is_alive = false;
}

/*
 * Looks up a process from the parent's list of children by PID.
 */
struct process *
child_process_from_pid(pid_t pid, struct process *parent) {
    lock_acquire(&parent->process_lock);

    struct process *child_proc = NULL;
    struct process *curr;
    for (struct list_elem *e = list_begin(&parent->children);
         e != list_end(&parent->children);
         e = list_next(e))
    {
        curr = list_entry(e, struct process, child_proc_elem);
        lock_acquire(&curr->process_lock);
        if (curr->pid == pid) {
            child_proc = curr;
            lock_release(&curr->process_lock);
            break;
        } else {
            lock_release(&curr->process_lock);
        }
    }

    lock_release(&parent->process_lock);

    return child_proc;
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
    unsigned char e_ident[16];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack(void **esp);

static bool validate_segment(const struct Elf32_Phdr *, struct file *);

static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load(const char *file_name, void (**eip)(void), void **esp) {
    struct thread *t = thread_current();
    struct Elf32_Ehdr ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    /* Allocate and activate page directory. */
    t->pagedir = pagedir_create();
    if (t->pagedir == NULL) {
        goto done;
    }
    process_activate();

    /* Open executable file. */
    file = filesys_open(file_name);
    if (file == NULL) {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }

    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr
        || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7)
        || ehdr.e_type != 2
        || ehdr.e_machine != 3
        || ehdr.e_version != 1
        || ehdr.e_phentsize != sizeof(struct Elf32_Phdr)
        || ehdr.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Elf32_Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file)) {
            goto done;
        }
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) {
            goto done;
        }
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
            /* Ignore this segment. */
            break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
            goto done;
        case PT_LOAD:
            if (validate_segment(&phdr, file)) {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0) {
                    /* Normal segment.
                       Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes = (
                            ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                            - read_bytes
                    );
                } else {
                    /* Entirely zero.
                       Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP (page_offset + phdr.p_memsz,
                                           PGSIZE);
                }
                if (!load_segment(
                        file, file_page, (void *) mem_page,
                        read_bytes, zero_bytes, writable
                )) {
                    goto done;
                }
            } else {
                goto done;
            }
            break;
        }
    }

    /* Set up stack. */
    if (!setup_stack(esp)) {
        goto done;
    }

    /* Start address. */
    *eip = (void (*)(void)) ehdr.e_entry;

    success = true;

    done:
    /* We arrive here whether the load is successful or not. */

    // If the file was loaded correctly, it must only be closed once the
    // execution of it has finished.
    if (success) {
        process_current()->executable = file;
        file_deny_write(file);
    } else {
        file_close(file);
    }

    return success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr *phdr, struct file *file) {
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) {
        return false;
    }

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (Elf32_Off) file_length(file)) {
        return false;
    }

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz) {
        return false;
    }

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0) {
        return false;
    }

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr((void *) phdr->p_vaddr)) {
        return false;
    }
    if (!is_user_vaddr((void *) (phdr->p_vaddr + phdr->p_memsz))) {
        return false;
    }

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr) {
        return false;
    }

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE) {
        return false;
    }

    /* It's okay. */
    return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
    ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT (pg_ofs(upage) == 0);
    ASSERT (ofs % PGSIZE == 0);

    file_seek(file, ofs);
    off_t start_pos = ofs;
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Calculate how to fill this page.
           We will read PAGE_READ_BYTES bytes from FILE
           and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct executable_location *exec_loc = malloc(
                sizeof(struct executable_location)
        );

        if (exec_loc == NULL) {
            return false;
        }

        exec_loc->file = file;
        exec_loc->page_read_bytes = page_read_bytes;
        exec_loc->start_pos = start_pos;
        exec_loc->writeable = writable;

        ASSERT(0 <= page_read_bytes && page_read_bytes <= PGSIZE);
        ASSERT(0 <= exec_loc->page_read_bytes && exec_loc->page_read_bytes <= PGSIZE);

        sp_add_entry(
                &process_current()->sp_table,
                upage,
                exec_loc,
                EXECUTABLE
        );

        /* Advance. */
        file_seek(file, (off_t) page_read_bytes);
        start_pos += page_read_bytes;
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }


    return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack(void **esp) {
    uint8_t *kpage;
    bool success = false;

    uint8_t *upage = ((uint8_t *) PHYS_BASE) - PGSIZE;
    kpage = vm_alloc_user_page(PAL_USER | PAL_ZERO, upage);
    if (kpage != NULL) {
        success = install_page(upage, kpage, true);
        if (success) {
            *esp = PHYS_BASE - 12;
        } else {
            vm_free_user_page(kpage);
        }
    }
    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page(void *upage, void *kpage, bool writable) {
    struct thread *t = thread_current();

    /* Verify that there's not already a page at that virtual
       address, then map our page there. */
    return (pagedir_get_page(t->pagedir, upage) == NULL
            && pagedir_set_page(t->pagedir, upage, kpage, writable));
}


/*
 * Hash function for open files.
 */
static unsigned
open_file_hash(const struct hash_elem *a, void *aux UNUSED) {
    struct open_file_s *open_file_s = hash_entry(
            a,
            struct open_file_s,
            fd_elem
    );
    return (unsigned int) open_file_s->fd;
}

/*
 * Less function for open files.
 */
static bool
open_file_less(const struct hash_elem *a, const struct hash_elem *b,
               void *aux UNUSED) {
    struct open_file_s *open_file_a = hash_entry(
            a,
            struct open_file_s,
            fd_elem
    );
    struct open_file_s *open_file_b = hash_entry(
            b,
            struct open_file_s,
            fd_elem
    );

    return open_file_a->fd < open_file_b->fd;
}

