#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "hash.h"
#include "vm/suppl_page.h"

#define EXIT_FAILURE -1
#define EXIT_SUCCESS 0

#define LOWEST_FILE_FD 2

/* Process identifier type */
typedef int pid_t;

/*
 * Contains a file opened by a process.
 */
struct open_file_s {
    int fd;                     /* The file descriptor */
    struct file *file;          /* Contents of loaded file */
    struct hash_elem fd_elem;   /* To put open files in a hash table of the process */
};

/*
 * Information processes must know.
 */
struct process {
    pid_t pid;                         /* Process id of a process  */
    char *executable_name;             /* The name of the file this process  executes. */
    struct file *executable;           /* The file this process executes. */
    int next_fd;                       /* Process' unique fd */
    int exit_status;                   /* Exit status of a thread. */
    struct hash open_files;            /* List of file descriptors of open files */
    struct semaphore wait_till_death;  /* When parent calls process_wait(),  it can block until this process finishes. */
    struct semaphore has_loaded;       /* For parent to block until process has  loaded. */
    bool loaded_correctly;             /* Tells parent that executed this process whether the executable file of this process was loaded correctly. */
    bool parent_is_alive;              /* So thread knows to free this struct once dead - this information is no longer required as parent cannot wait on this process. */
    struct list children;              /* List<struct thread *> of child processes. */
    struct lock process_lock;          /* Locks the whole process struct in order to avoid race conditions. */
    struct list_elem child_proc_elem;  /* To put in list of parent's children. */
    struct sp_table sp_table;  /* Supplemental page table used to store information about pages for virtual memory*/
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct process *process_current(void);
struct process *child_process_from_pid(pid_t pid, struct process *parent);

struct file *process_get_open_file(int fd);
struct open_file_s *process_get_open_file_struct(int fd);

void setup_test_process(void);
void tear_down_test_process(void);

void open_files_destroy_func (struct hash_elem *e, void *aux UNUSED);

#endif /* userprog/process.h */
