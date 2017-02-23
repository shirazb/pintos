#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <threads/vaddr.h>
#include <devices/shutdown.h>
#include <filesys/filesys.h>
#include <filesys/file.h>
#include <devices/input.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"

#define BYTE_SIZE 8

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
static uint8_t *get_syscall_param_addr(void *esp, int index);
static void fail_if_invalid_user_addr(const void *addr);
static void return_value(struct intr_frame *f, void *val);

/* Table of syscalls */
typedef void (*syscall_f)(struct intr_frame *f);
static inline void init_syscalls_table(void);
static syscall_f syscall_table[NUM_SYSCALLS];

/* System calls */
static void sys_inumber(struct intr_frame *f);
static void sys_isdir(struct intr_frame *f);
static void sys_readdir(struct intr_frame *f);
static void sys_mkdir(struct intr_frame *f);
static void sys_chdir(struct intr_frame *f);
static void sys_munmap(struct intr_frame *f);
static void sys_mmap(struct intr_frame *f);
static void sys_close(struct intr_frame *f);
static void sys_tell(struct intr_frame *f);
static void sys_seek(struct intr_frame *f);
static void sys_write(struct intr_frame *f);
static void sys_read(struct intr_frame *f);
static void sys_filesize(struct intr_frame *f);
static void sys_open(struct intr_frame *f);
static void sys_remove(struct intr_frame *f);
static void sys_create(struct intr_frame *f);
static void sys_wait(struct intr_frame *f);
static void sys_exec(struct intr_frame *f);
static void sys_exit(struct intr_frame *f);
static void sys_halt(struct intr_frame *f);

static struct lock filesys_lock;

void
syscall_init(void) {
    init_syscalls_table();
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
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
 * Validates stack pointer then gets a parameter from the stack.
 */
// FIXME: Dont we need to validate the address of the parameter not esp?
static uint8_t *
get_syscall_param_addr(void *esp, int index) {
    fail_if_invalid_user_addr(esp);

    // Remove syscall number + index of argument
    // Note, all syscall parameters in Pintos are 32 bits.
    return (uint8_t *) ((uint32_t *) esp + 1 + index);
}

/*
 * Calls thread exit if addr is null or not in user space
 */
static void
fail_if_invalid_user_addr(const void *addr) {
    if (addr == NULL || !is_user_vaddr(addr)) {
        exit_process(EXIT_FAILURE);
    }
}

/*
 * Returns a value from the system call. Takes a pointer to the value to return.
 */
static void
return_value(struct intr_frame *f, void *val) {
    f->eax = * (uint32_t *) val;
}

/*
 * Exits a process -- sets its exit status and then exits the thread
 */
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

    uint8_t *exit_status_addr = get_syscall_param_addr(f->esp, 0);
    int exit_status = read_user_word(exit_status_addr);
    exit_process(exit_status);
}

static void
sys_exec(struct intr_frame *f) {
    // TODO: Make a macro that does type punning to ensure bit sequence is
    // maintinated when casting.
    // TODO: Make 1 function / macro that gets the addr, derefs its and does
    // the type pun. Perhaps put this in a different file.
    const char *cmd_line = (const char *) read_user_word(get_syscall_param_addr
                                                          (f->esp, 0));

    // Do we want to lock across all of process_execute()?
    lock_filesys();
    tid_t id = process_execute(cmd_line);
    release_filesys();

    // TODO: Wait till we know executable has been successfully loaded.
    // If program cannot be loaded, return -1

    // TODO: Should process_execute() be returning a PID now?
    // TODO: Use return_value().
    f->eax = id;
}

static void
sys_wait(struct intr_frame *f) {
    tid_t child = read_user_word(get_syscall_param_addr(f->esp, 0));
    int exit_status = process_wait(child);
    // Type pun to ensure bit pattern maintained in signed to unsigned cast.
    f->eax = * (uint32_t *) &exit_status;
}

static void
sys_create(struct intr_frame *f) {
    tid_t arg1 = read_user_word(get_syscall_param_addr(f->esp, 1));
    tid_t arg2 = read_user_word(get_syscall_param_addr(f->esp, 2));
    lock_filesys();
//    arg2 is supposed to be of type off_t which is a int32
    f->eax = filesys_create((char *)arg1, arg2);
    release_filesys();
}

static void sys_remove(struct intr_frame *f) {
    tid_t arg = read_user_word(get_syscall_param_addr(f->esp, 1));
    lock_filesys();
    f->eax = filesys_remove((char *) arg);
    release_filesys();
}

static void sys_open(struct intr_frame *f) {
    tid_t arg = read_user_word(get_syscall_param_addr(f->esp, 1));
    lock_filesys();
    struct file * file = filesys_open((char *) arg);
    release_filesys();
//    is this best way to check if file is empty/valid?
//    how to add file to thread?
//    f->eax = (file == NULL) ? -1 : file
}

// FIXME: Is this the right file?
static void sys_filesize(struct intr_frame *f) {
    tid_t arg = read_user_word(get_syscall_param_addr(f->esp, 1));
    lock_filesys();
    struct file *file = filesys_open((char *) arg);
    release_filesys();
    f->eax = file_length(file);
//    printf("ERROR SYSCALL NOT IMPLEMENTED: filesize()");
}

/*int read (int fd, void *buffer, unsigned size)
Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually
read (0 at end of file), or -1 if the file could not be read (due to a condition other than
end of file). Fd 0 reads from the keyboard using input_getc(), which can be found in
‘src/devices/input.h’.*/
static void sys_read(struct intr_frame *f) {
    tid_t fd = read_user_word(get_syscall_param_addr(f->esp, 1));
    tid_t buffer = read_user_word(get_syscall_param_addr(f->esp, 2));
    tid_t size = read_user_word(get_syscall_param_addr(f->esp, 3));

//    f->eax = (/*if file can be read*/) ? input_getc() : -1;


//    printf("ERROR SYSCALL NOT IMPLEMENTED: read()");
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

//    hex_dump(0, f->esp, 16, false);

    int fd = read_user_word(get_syscall_param_addr(f->esp, 0));
    char *buffer = (char *) read_user_word(get_syscall_param_addr(f->esp, 1));
    unsigned size = (unsigned int) read_user_word(
            get_syscall_param_addr(f->esp, 2));
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
//    get arguments
    int fd = read_user_word(get_syscall_param_addr(f->esp, 1));
    unsigned position = (unsigned) read_user_word(get_syscall_param_addr(f->esp, 2));

    lock_filesys();
//    get file descriptor
//    if descriptor not null use file_seek(file, position)
    struct open_file *open_file = process_get_open_file_struct (fd);
    if (open_file != NULL) {
        file_seek (open_file->open_file, position);
    }
//
    release_filesys();
//    printf("ERROR SYSCALL NOT IMPLEMENTED: seek()");
}
/*unsigned tell (int fd)
Returns the position of the next byte to be read or written in open file fd, expressed in bytes
from the beginning of the file.*/
static void sys_tell(struct intr_frame *f) {
    // get argument
    int fd = read_user_word(get_syscall_param_addr(f->esp, 1));

    lock_filesys();

    unsigned position = 0;

    // get file descriptor
    struct open_file *open_file = process_get_open_file_struct (fd);
    if (open_file != NULL)
        position = (unsigned)file_tell (open_file->open_file);

    release_filesys();

    /* Return the result by setting the eax value in the interrupt frame. */
    f->eax = position;
}

/*
 * void close (int fd)
Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file
descriptors, as if by calling this function for each one.*/
static void sys_close(struct intr_frame *f) {
//   get argument
    int fd = read_user_word(get_syscall_param_addr(f->esp, 1));

    struct open_file *open_file = process_get_open_file_struct (fd);
//    close_syscall(open_file, true);
}

/*void
close_syscall (struct file_descriptor *file_descriptor,
               bool remove_file_descriptor_table_entry)
{
  start_file_system_access ();

 // Close the file if it was found.
if (file_descriptor != NULL) {
file_close (file_descriptor->file);

if (remove_file_descriptor_table_entry) {
// Remove the entry from the open files hash table.
struct file_descriptor descriptor;
descriptor.fd = file_descriptor->fd;
hash_delete (&thread_current ()->proc_info->file_descriptor_table,
&descriptor.hash_elem);
}
free(file_descriptor);
}

end_file_system_access ();
}*/


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
    printf("ERROR SYSCALL NOT IMPLEMENTED: mmap()");
}

static void sys_munmap(struct intr_frame *f) {
    printf("ERROR SYSCALL NOT IMPLEMENTED: munmao()");
}

static void sys_chdir(struct intr_frame *f) {
    printf("ERROR SYSCALL NOT IMPLEMENTED: chdir()");
}

static void sys_mkdir(struct intr_frame *f) {
    printf("ERROR SYSCALL NOT IMPLEMENTED: mkdir()");
}

static void sys_readdir(struct intr_frame *f) {
    printf("ERROR SYSCALL NOT IMPLEMENTED: readdir()");
}

static void sys_isdir(struct intr_frame *f) {
    printf("ERROR SYSCALL NOT IMPLEMENTED: isdir()");
}

static void sys_inumber(struct intr_frame *f) {
    printf("ERROR SYSCALL NOT IMPLEMENTED: inumber()");
}
