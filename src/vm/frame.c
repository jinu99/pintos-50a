#include "filesys/file.h"
#include <stdio.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "lib/kernel/hash.h"

void frame_table_init (void) {
  hash_init(&frame_table, frame_hash_function, frame_less_function, NULL);
  lock_init(&frame_lock);
}

void* frame_alloc (enum palloc_flags flags, struct sup_page_elem *spte) {
  if ((flags & PAL_USER) == 0)
    return NULL;
      
  void *frame = palloc_get_page(flags);
  if (frame)
    frame_add_to_table(frame, spte);
  else 
    PANIC ("Frame could not be allocated because frame is full!");
    
  /*else {
    while (!frame) {
      frame = frame_evict(flags);
      lock_release(&frame_table_lock); 
    }
    if (!frame)
      PANIC ("Frame could not be evicted because swap is full!");
      
    frame_add_to_table(frame, spte); 
  }*/
  print_frame_table(0);
  return frame;
}

void frame_free (void *frame) {
  struct hash_iterator i;
  lock_acquire(&frame_lock);
  
  hash_first (&i, &frame_table);
  while (hash_next(&i)) {
    struct frame_table_elem *elem = hash_entry(i.elem, struct frame_table_elem, frame_elem);
    if (elem->frame == frame) {
      hash_delete(&frame_table, &elem->frame_elem);
      free(elem);
      palloc_free_page(frame);
      break;
    }
  }
  lock_release(&frame_lock);
  print_frame_table(1);
}

void frame_add_to_table (void *frame, struct sup_page_elem *spte)
{
  struct frame_table_elem *elem = malloc(sizeof(struct frame_table_elem));
  elem->frame = frame;
  elem->spte = spte;
  elem->holder = thread_current();
  lock_acquire(&frame_lock);
  hash_insert(&frame_table, &elem->frame_elem);
  lock_release(&frame_lock);
}

/*void* frame_evict (enum palloc_flags flags)
{
  lock_acquire(&frame_table_lock);
  struct list_elem *e = list_begin(&frame_table);
  
  while (true)
    {
      struct frame_table_elem *elem = list_entry(e, struct frame_table_elem, elem);
      if (!elem->spte->pinned)
	{
	  struct thread *t = elem->thread;
	  if (pagedir_is_accessed(t->pagedir, elem->spte->uva))
	    {
	      pagedir_set_accessed(t->pagedir, elem->spte->uva, false);
	    }
	  else
	    {
	      if (pagedir_is_dirty(t->pagedir, elem->spte->uva) ||
		  elem->spte->type == SWAP)
		{
		  if (elem->spte->type == MMAP)
		    {
		      lock_acquire(&filesys_lock);
		      file_write_at(elem->spte->file, elem->frame,
				    elem->spte->read_bytes,
				    elem->spte->offset);
		      lock_release(&filesys_lock);
		    }
		  else
		    {
		      elem->spte->type = SWAP;
		      elem->spte->swap_index = swap_out(elem->frame);
		    }
		}
	      elem->spte->is_loaded = false;
	      list_remove(&elem->elem);
	      pagedir_clear_page(t->pagedir, elem->spte->uva);
	      palloc_free_page(elem->frame);
	      free(elem);
	      return palloc_get_page(flags);
	    }
	}
      e = list_next(e);
      if (e == list_end(&frame_table))
	{
	  e = list_begin(&frame_table);
	}
    }
}*/

unsigned frame_hash_function (const struct hash_elem *e, void *aux) {
  struct frame_table_elem *elem = hash_entry(e, struct frame_table_elem, frame_elem);
  
  return hash_bytes(&elem->frame, sizeof(elem->frame));
}

bool frame_less_function (const struct hash_elem *a, const struct hash_elem *b, void *aux) {
  struct frame_table_elem *elem_a = hash_entry(a, struct frame_table_elem, frame_elem);
  struct frame_table_elem *elem_b = hash_entry(b, struct frame_table_elem, frame_elem);
    
  return elem_a->frame < elem_b->frame;
}


void print_frame_table(int mode){
  struct hash_iterator i;
  int n = 0;
  
  lock_acquire(&frame_lock);
  switch(mode){
  case 0: printf("after allocation\n"); break;
  case 1: printf("after free\n"); break;
  }
  
  printf("=======================================================\n");
  hash_first(&i, &frame_table);
  while(hash_next(&i)){
    struct frame_table_elem *elem = hash_entry(hash_cur(&i), struct frame_table_elem, frame_elem);
    printf("%2d: { Thread %s, VA 0x%x, SPTE 0x%x }\n", n++, elem->holder->name, elem->frame, elem->spte);
  }
  printf("=======================================================\n");
  lock_release(&frame_lock);
}
