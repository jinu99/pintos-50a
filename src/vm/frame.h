#ifndef __VM_FRAME_H
#define __VM_FRAME_H

#include "threads/palloc.h"
#include "threads/synch.h"
#include <stdbool.h>
#include <stdint.h>
#include "lib/kernel/list.h"

struct list frame_table;
struct lock frame_lock;

struct frame_table_elem {
  void *user_page;
  
  struct list_elem frame_elem;
  struct thread *holder;
  
  bool pinned;
};

void frame_table_init (void);
void* frame_alloc (enum palloc_flags flags/*, struct sup_page_entry *spte*/);
void frame_free (void *frame);
void frame_add_to_table (void *frame/*, struct sup_page_entry *spte*/);
/*void* frame_evict (enum palloc_flags flags);*/


#endif
