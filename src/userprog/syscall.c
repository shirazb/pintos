#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <threads/vaddr.h>
#include <devices/shutdown.h>
#include <filesys/filesys.h>
#include <filesys/file.h>
#include <devices/input.h>
#include <threads/malloc.h>
#include <lib/kernel/stdio.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"

#define BYTE_SIZE 8

/*
 * Declares a variable called PARAM of type TYPE. Initialises it to parameter
 * number INDEX taken from the stack frame pointed to by ESP.
 *
 * Intended for use only in system call handlers to retrieve their arguments
 * from the given stack frame safely.
 *
 * Uses a type pun to ensure the bit pattern of the parameter is unchanged.
 * Reserves the local variable "__word_PARAM".
 * Note that this macro is a statement. Do not use it in an expression.
 */
#define decl_parameter(TYPE, PARAM, ESP, INDEX) int __word_##PARAM = read_user_word(get_syscall_param_addr((ESP), (INDEX))); \
TYPE PARAM = * (TYPE *) &__word_##PARAM

/* System call handler */
static void syscall_handler(struct intr_frame *);
static int get_syscall_number(struct intr_frame *);

/* File system synchronisation */
static inline void lock_filesys(void);
static inline void release_filesys(void);

/* Exits a process - sets its exit status and then exits the thread */
static void exit_process(int status);

/* Safe access of user memory */
static int get_user(const uint8_t *uaddr);
static int read_user_word(uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
static inline uint8_t *get_syscall_param_addr(void *esp, int index);
static inline void fail_if_invalid_user_addr(const void *addr);
static inline void return_value(struct intr_frame *f, void *val);

/* Table of syscalls */
typedef void (syscall_f)(struct intr_frame *);
static inline void init_syscalls_table(void);
static syscall_f * syscall_table[NUM_SYSCALLS];

/* System calls */
static syscall_f sys_inumber;
static syscall_f sys_isdir;
static syscall_f sys_readdir;
static syscall_f sys_mkdir;
static syscall_f sys_chdir;
static syscall_f sys_munmap;
static syscall_f sys_mmap;
static syscall_f sys_close;
static syscall_f sys_tell;
static syscall_f sys_seek;
static syscall_f sys_write;
static syscall_f sys_read;
static syscall_f sys_filesize;
static syscall_f sys_open;
static syscall_f sys_remove;
static syscall_f sys_create;
static syscall_f sys_wait;
static syscall_f sys_exec;
static syscall_f sys_exit;
static syscall_f sys_halt;

static struct lock filesys_lock;

void
syscall_init(void) {
    init_syscalls_table();
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
}

/*
 * Returns a value from the system call. Takes a pointer to the value to
 * return, so that a type pun is performed. This ensures the bit pattern of
 * *val is preserved.
 */
static inline void
return_value(struct intr_frame *f, void *val) {
    f->eax = * (uint32_t *) val;
}

static inline void
lock_filesys(void) {
    lock_acquire(&filesys_lock);
}

static inline void
release_filesys(void) {
    lock_release(&filesys_lock);
}

static inline void
init_syscalls_table(void) {
    syscall_table[SYS_HALT]     = &sys_halt;
    syscall_table[SYS_EXIT]     = &sys_exit;
    syscall_table[SYS_EXEC]     = &sys_exec;
    syscall_table[SYS_WAIT]     = &sys_wait;
    syscall_table[SYS_CREATE]   = &sys_create;
    syscall_table[SYS_REMOVE]   = &sys_remove;
    syscall_table[SYS_OPEN]     = &sys_open;
    syscall_table[SYS_FILESIZE] = &sys_filesize;
    syscall_table[SYS_READ]     = &sys_read;
    syscall_table[SYS_WRITE]    = &sys_write;
    syscall_table[SYS_SEEK]     = &sys_seek;
    syscall_table[SYS_TELL]     = &sys_tell;
    syscall_table[SYS_CLOSE]    = &sys_close;
    syscall_table[SYS_MMAP]     = &sys_mmap;
    syscall_table[SYS_MUNMAP]   = &sys_munmap;
    syscall_table[SYS_CHDIR]    = &sys_chdir;
    syscall_table[SYS_MKDIR]    = &sys_mkdir;
    syscall_table[SYS_READDIR]  = &sys_readdir;
    syscall_table[SYS_ISDIR]    = &sys_isdir;
    syscall_table[SYS_INUMBER]  = &sys_inumber;
}

/**
 * The system call handler. Gets syscall number from the stack and dispatches
 * to appropriate syscall.
 */
static void
syscall_handler(struct intr_frame *f) {
    ASSERT(f != NULL);
    int syscall_num = get_syscall_number(f);

    // Perform system call
    syscall_table[syscall_num](f);
}

/*
 * Returns the system call number, read from the stack of the user program that
 * made the syscall.
 */
static int
get_syscall_number(struct intr_frame *f) {
    // Get 32 bits from esp then convert to uintptr_t for valid comparisons
    // later
    uint32_t *syscall_num_addr = (uint32_t *) f->esp;

    // Get syscall number from user stack
    int syscall_num = read_user_word((uint8_t *) syscall_num_addr);

    // Check number is valid
    if (syscall_num < 0 || syscall_num > NUM_SYSCALLS - 1) {
        exit_process(EXIT_FAILURE);
    }

    return syscall_num;
}

/*
 * Reads a byte at user virtual address UADDR. UADDR must be below PHYS_BASE.
 * Returns the byte value if successful, -1 if a segfault occurred.
 */
static int
get_user(const uint8_t *uaddr) {
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:": "=&a" (result) : "m" (*uaddr));
    return result;
}

/*
 * Reads 4 bytes at user virtual address UADDR. UADDR must be below PHYS_BASE.
 * Returns the byte value if successful, exits with -1 if a segfault occurred.
 * Does perform validation of the user address.
 */
static int
read_user_word(uint8_t *uaddr) {
    const int n = sizeof(uint32_t) / sizeof(uint8_t);

    uint8_t *byte_addr;
    int word = 0;
    int temp = 0;

    for (int i = 0; i < n; i++) {
        byte_addr = uaddr + i;

        fail_if_invalid_user_addr(byte_addr);
        temp = get_user(byte_addr);
        if (temp == -1) {
            exit_process(EXIT_FAILURE);
            NOT_REACHED();
        }

        temp <<= i * BYTE_SIZE;
        word = word | temp;
    }

    return word;
}

/* Writes BYTE to user address UDST. UDST must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */
static bool
put_user(uint8_t *udst, uint8_t byte) {
    int error_code;
    asm ("movl $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*udst)
    : "q" (byte));
    return error_code != -1;
}


/*
 * Calls thread exit if addr is null or not in user space
 */
static inline void
fail_if_invalid_user_addr(const void *addr) {
    if (addr == NULL || !is_user_vaddr(addr)) {
        exit_process(EXIT_FAILURE);
        NOT_REACHED();
    }
}

/*
 * Validates stack pointer then gets a parameter from the stack.
 */
static inline uint8_t *
get_syscall_param_addr(void *esp, int index) {
    // Remove syscall number + index of argument
    // Note, all syscall parameters in Pintos are 32 bits.
    uint8_t *addr = (uint8_t *) ((uint32_t *) esp + 1 + index);
    fail_if_invalid_user_addr(addr);
    return addr;
}

/*
 * Exits a process -- sets its exit status and then exits the thread
 */
// TODO: Should exit codes be uint8_t?
static void
exit_process(int status) {
    struct thread *curr = thread_current();

    ASSERT(curr != NULL)
    ASSERT(curr->process != NULL);

    lock_acquire(&curr->process->process_lock);
    curr->process->exit_status = status;
    lock_release(&curr->process->process_lock);

    process_exit();
    NOT_REACHED();
}

/************* System calls *************/

// TODO: make arg void
static void
sys_halt(struct intr_frame *f) {
    shutdown_power_off();
}

static void
sys_exit(struct intr_frame *f) {
    ASSERT(f != NULL);

    decl_parameter(int, exit_status, f->esp, 0);

    exit_process(exit_status);
}

static void
sys_exec(struct intr_frame *f) {
    decl_parameter(const char *, cmd_line, f->esp, 0);

    // Do we want to lock across all of process_execute()?
    tid_t child_tid = process_execute(cmd_line);

    // If process_execute failed, fail.
    if (child_tid == TID_ERROR) {
        exit_process(EXIT_FAILURE);
        NOT_REACHED();
    }

    // Get the child process struct.
    struct process *child = process_lookup(child_tid, process_current());
    ASSERT(child != NULL);

    // Wait for program to be loaded. If loaded correctly, return -1.
    sema_down(&child->has_loaded);
    int result = child->loaded_correctly ? child_tid : TID_ERROR;

    return_value(f, &result);
}

static void
sys_wait(struct intr_frame *f) {
    decl_parameter(tid_t, child, f->esp, 0);
    int exit_status = process_wait(child);
    return_value(f, &exit_status);
}

static void
sys_create(struct intr_frame *f) {
    decl_parameter(char *, file_name, f->esp, 0);
    decl_parameter(unsigned int, initial_size, f->esp, 1);
    if (file_name == NULL) {
        exit_process(EXIT_FAILURE);
        NOT_REACHED();
    }

    lock_filesys();
    bool success = filesys_create(file_name, (off_t) initial_size);
    release_filesys();

    return_value(f, &success);
}

static void sys_remove(struct intr_frame *f) {
    decl_parameter(char *, file_name, f->esp, 0);

    lock_filesys();
    bool success = filesys_remove(file_name);
    release_filesys();

    return_value(f, &success);
}

static int generate_fd (struct process *p) {
    lock_acquire(&p->process_lock);
    int fd = p->next_fd++;
    lock_release(&p->process_lock);

    return fd;
}

static void sys_open(struct intr_frame *f) {
    decl_parameter(char *, file_name, f->esp, 0);

    if (file_name == NULL) {
        exit_process(EXIT_FAILURE);
        NOT_REACHED();
    }

    lock_filesys();
    struct file *file = filesys_open(file_name);
    release_filesys();

    int fd = -1;

    if (file != NULL) {
        ASSERT(process_current()->next_fd >= LOWEST_FILE_FD);

        // Reserve space for the open_file_s entry to put in the hash entry in process struct
        struct open_file_s *open_file_s = malloc(sizeof(struct open_file_s));

        // if malloc fails then exit
        if (open_file_s == NULL) {
            process_exit();
            NOT_REACHED();
        }

        fd = generate_fd(process_current());
        open_file_s->open_file = file;
        open_file_s->fd = fd;

        hash_insert(&process_current()->open_files, &open_file_s->fd_elem);
    }

    return_value(f, &fd);
}

/*int filesize (int fd)
Returns the size, in bytes, of the file open as fd. */
static void sys_filesize(struct intr_frame *f) {
    decl_parameter(int, file_name, f->esp, 0);

    lock_filesys();
    struct open_file_s *open_file_s = process_get_open_file_struct(file_name);
    off_t length = file_length(open_file_s->open_file);
    release_filesys();

    return_value(f, &length);
}

/*int read (int fd, void *buffer, unsigned size)
Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually
read (0 at end of file), or -1 if the file could not be read (due to a condition other than
end of file). Fd 0 reads from the keyboard using input_getc(), which can be found in
‘src/devices/input.h’.*/
// TODO: How can we check if file can be read?
static void sys_read(struct intr_frame *f) {
    decl_parameter(int, fd, f->esp, 0);
    decl_parameter(void *, buffer, f->esp, 1);
    decl_parameter(unsigned, size, f->esp, 2);

    bool file_can_be_read = true;
    int exit_failure = EXIT_FAILURE;

//  if fd is -1, it means we are trying to read from STDOUT so error
    if (fd == -1) {
        return_value(f, &exit_failure);
    } else if (fd == 0) {
        //  validate buffer
        fail_if_invalid_user_addr(buffer);
        uint8_t *buff = (uint8_t *) buffer;

        lock_filesys();
        for (int i = 0 ; i < size; i++) {
            buff[i] = input_getc();
        }
        release_filesys();

        return_value(f, buff);
    } else {
//      check fd >= 2
        if (fd < 2) {
            return_value(f, &exit_failure);
        }

        //  validate buffer
        fail_if_invalid_user_addr(buffer);

        struct open_file_s *open_file_s = process_get_open_file_struct((unsigned int) fd);

        if (open_file_s == NULL) {
            exit_process(EXIT_FAILURE);
            NOT_REACHED();
        }

        struct hash_elem *fd_elem = hash_find(&process_current()->open_files, &open_file_s->fd_elem);

//      fd needs to exist and be valid
        if (fd_elem == NULL) {
            file_can_be_read = false;
        }

        uint8_t *buff = (uint8_t *) buffer;

        lock_filesys();
        int read_file = file_read(open_file_s->open_file, buff, size);
        release_filesys();

        int result = (file_can_be_read) ? read_file : EXIT_FAILURE;
        return_value(f, &result);
    }

}

/*
 * int write(int fd, const void *buffer, unsigned size)
 * Writes size bytes from buffer to the open file fd. Does not write past the
 * end of a file.
 * Returns the number of bytes actually written.
 */
static void
sys_write(struct intr_frame *f) {
    ASSERT(f != NULL);

    decl_parameter(int, fd, f->esp, 0);
    decl_parameter(char *, buffer, f->esp, 1);
    decl_parameter(unsigned, size, f->esp, 2);

    unsigned bytes_written = 0;

    // Write to console.
    if (fd == 1) {
        // TODO: Break up the buffer if size more than a few hundred bytes
        putbuf(buffer, size);
        bytes_written = size;
    } else {
        // Get the file represented by the given file descriptor
        struct file *dst = process_get_open_file(fd);

        // Terminate the process if the file did not exist
        if (dst == NULL) {
            exit_process(EXIT_FAILURE);
        }

        lock_filesys();
        bytes_written = (unsigned) file_write(dst, buffer, size);
        release_filesys();
    }

    return_value(f, &bytes_written);
}

/* void seek (int fd, unsigned position) */
static void
sys_seek(struct intr_frame *f) {
    decl_parameter(int, fd, f->esp, 0);
    decl_parameter(unsigned, position, f->esp, 0);

    lock_filesys();

    // If descriptor not null use file_seek(file, position)
    struct open_file_s *open_file = process_get_open_file_struct (fd);
    if (open_file != NULL) {
        file_seek (open_file->open_file, position);
    }

    release_filesys();
}
/*unsigned tell (int fd)
Returns the position of the next byte to be read or written in open file fd, expressed in bytes
from the beginning of the file.*/
static void sys_tell(struct intr_frame *f) {
    decl_parameter(int, fd, f->esp, 0);

    unsigned position = 0;

    struct open_file_s *open_file = process_get_open_file_struct (fd);
    if (open_file != NULL) {
        lock_filesys();
        position = (unsigned) file_tell (open_file->open_file);
        release_filesys();
    }

    /* Return the result by setting the eax value in the interrupt frame. */
    return_value(f, &position);
}

void
close_syscall(struct open_file_s *file_descriptor,
              bool remove_fd_entry) {

    lock_filesys();

    // If the file is found, close it
    if (file_descriptor != NULL) {
        file_close(file_descriptor->open_file);

// Remove the entry from the open_files hash table.
        if (remove_fd_entry) {
            struct open_file_s open_file;
            open_file.fd = file_descriptor->fd;
//            list_remove(&open_file_s.fd_elem);
            hash_delete(&thread_current()->process->open_files,
                        &open_file.fd_elem);
        }
        free(file_descriptor);
    }

    release_filesys();
}

/*
 * void close (int fd)
Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file
descriptors, as if by calling this function for each one.*/
static void sys_close(struct intr_frame *f) {
    decl_parameter(int, fd, f->esp, 0);

    struct open_file_s *open_file = process_get_open_file_struct (fd);

    close_syscall(open_file, true);
}


/*mapid_t mmap (int fd, void *addr)
Maps the file open as fd into the process’s virtual address space. The entire file is mapped
into consecutive virtual pages starting at addr.

Your VM system must lazily load pages in mmap regions and use the mmaped file itself as
backing store for the mapping. That is, evicting a page mapped by mmap writes it back to
the file it was mapped from.
If the file’s length is not a multiple of PGSIZE, then some bytes in the final mapped page
“stick out” beyond the end of the file. Set these bytes to zero when the page is faulted in
from the file system, and discard them when the page is written back to disk.
If successful, this function returns a “mapping ID” that uniquely identifies the mapping within
the process. On failure, it must return -1, which otherwise should not be a valid mapping id,
and the process’s mappings must be unchanged.
A call to mmap may fail if the file open as fd has a length of zero bytes. It must fail if addr is
not page-aligned or if the range of pages mapped overlaps any existing set of mapped pages,
including the stack or pages mapped at executable load time. It must also fail if addr is 0,
because some Pintos code assumes virtual page 0 is not mapped. Finally, file descriptors 0
and 1, representing console input and output, are not mappable.*/
static void sys_mmap(struct intr_frame *f) {
    ASSERT("ERROR SYSCALL NOT IMPLEMENTED: mmap()");
}

static void sys_munmap(struct intr_frame *f) {
    ASSERT("ERROR SYSCALL NOT IMPLEMENTED: munmao()");
}

static void sys_chdir(struct intr_frame *f) {
    ASSERT("ERROR SYSCALL NOT IMPLEMENTED: chdir()");
}

static void sys_mkdir(struct intr_frame *f) {
    ASSERT("ERROR SYSCALL NOT IMPLEMENTED: mkdir()");
}

static void sys_readdir(struct intr_frame *f) {
    ASSERT("ERROR SYSCALL NOT IMPLEMENTED: readdir()");
}

static void sys_isdir(struct intr_frame *f) {
    ASSERT("ERROR SYSCALL NOT IMPLEMENTED: isdir()");
}

static void sys_inumber(struct intr_frame *f) {
    ASSERT("ERROR SYSCALL NOT IMPLEMENTED: inumber()");
}

