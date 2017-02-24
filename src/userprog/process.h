#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "hash.h"

#define EXIT_FAILURE -1
#define EXIT_SUCCESS 0

/* Process identifier type */
typedef int pid_t;

struct open_file {
    unsigned int fd;                      /* The file descriptor */
    struct file *open_file;      /* Contents of loaded file */
    struct hash_elem fd_elem;    /* To put fds in a hash table */
};

struct process {
    pid_t pid;               /* Process id of a process  */
    char *file_name;
    int exit_status;         /* Exit status of a thread. */
    struct hash open_files;  /* List of file descriptors of open files */
    struct semaphore wait_till_death; /* When parent calls process_wait(), it can block until this process finishes. */
    bool parent_is_alive;     /* So thread knows to free this struct once dead - this information is no longer required as parent cannot wait on this process. */
    struct list children;     /* Hash<TID, struct thread *> of child processes. */
    struct lock process_lock; /* Locks a whole process struct in order to
                                 avoid race conditions. */
};

void process_init_system(void);
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct process *process_current(void);
struct file *process_get_open_file(int fd);
void process_destroy(struct process *p);
struct open_file *process_get_open_file_struct(int fd);

void setup_test_process(void);
void tear_down_test_process(void);

#endif /* userprog/process.h */
