#ifndef __VM_FRAME_H
#define __VM_FRAME_H

#include "threads/palloc.h"
#include "threads/synch.h"
#include <stdbool.h>
#include <stdint.h>
#include "lib/kernel/hash.h"

struct hash frame_table;
struct lock frame_lock;

struct frame_table_elem {
  void *user_page;
  
  struct hash_elem frame_elem;
  struct thread *holder;
  
  bool pinned;
};

void frame_table_init (void);
void* frame_alloc (enum palloc_flags flags/*, struct sup_page_entry *spte*/);
void frame_free (void *frame);
void frame_add_to_table (void *frame/*, struct sup_page_entry *spte*/);
/*void* frame_evict (enum palloc_flags flags);*/

unsigned hash_function (const struct hash_elem *e, void *aux);
bool hash_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);

#endif
