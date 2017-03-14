#ifndef PINTOS_VM_H
#define PINTOS_VM_H

#include <threads/palloc.h>

//TODO
#define MAX_STACK_SIZE (PGSIZE * 8)

void vm_init(void);
void * vm_alloc_user_page(enum palloc_flags flags, void *upage);
void vm_free_user_page(void *kpage);
void *vm_handle_page_fault(void *upage, void *esp);


#endif //PINTOS_VM_H
