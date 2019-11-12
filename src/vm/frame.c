#include "filesys/file.h"
#include <stdio.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "lib/kernel/list.h"

void frame_table_init (void) {
  list_init(&frame_table);
  lock_init(&frame_lock);
}

void* frame_alloc (enum palloc_flags flags/*, struct sup_page_entry *spte*/) {
  if ((flags & PAL_USER) == 0)
    return NULL;
  void *frame = palloc_get_page(flags);

  if (frame){
    printf("alloc 0x%x\n", frame);
    frame_add_to_table(frame/*, spte*/);
  }
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
  }
  */
  print_frame_table(0);
  return frame;
}

void frame_free (void *frame) {
  lock_acquire(&frame_lock);
  printf("free 0x%x\n", frame);
  struct list_elem *e;
  for(e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
    struct frame_table_elem *elem = list_entry(e, struct frame_table_elem, frame_elem);
    if (elem->user_page == frame) {
      list_remove(&elem->frame_elem);
      free(elem);
      palloc_free_page(frame);
      break;
    }
  }
  lock_release(&frame_lock);
  print_frame_table(1);
}

void frame_add_to_table (void *frame/*, struct sup_page_entry *spte*/)
{
  struct frame_table_elem *elem = malloc(sizeof(struct frame_table_elem));
  elem->user_page = frame;
  //fte->spte = spte;
  elem->holder = thread_current();
  lock_acquire(&frame_lock);
  list_push_back(&frame_table, &elem->frame_elem);
  lock_release(&frame_lock);
}

void print_frame_table(int mode){
  struct list_elem *e;
  int n = 0;
  
  lock_acquire(&frame_lock);
  switch(mode){
  case 0: printf("after allocation\n"); break;
  case 1: printf("after free\n"); break;
  }
  printf("=====================================================\n");
  for(e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
    struct frame_table_elem *elem = list_entry(e, struct frame_table_elem, frame_elem);
    printf("%2d: { Thread %s, VA 0x%x, Pinned %s }\n", n++, elem->holder->name, elem->user_page, elem->pinned ? "true" : "false");
  }
  printf("=====================================================\n");
  lock_release(&frame_lock);
}
/*void* frame_evict (enum palloc_flags flags)
{
  lock_acquire(&frame_table_lock);
  struct list_elem *e = list_begin(&frame_table);
  
  while (true)
    {
      struct frame_entry *fte = list_entry(e, struct frame_entry, elem);
      if (!fte->spte->pinned)
	{
	  struct thread *t = fte->thread;
	  if (pagedir_is_accessed(t->pagedir, fte->spte->uva))
	    {
	      pagedir_set_accessed(t->pagedir, fte->spte->uva, false);
	    }
	  else
	    {
	      if (pagedir_is_dirty(t->pagedir, fte->spte->uva) ||
		  fte->spte->type == SWAP)
		{
		  if (fte->spte->type == MMAP)
		    {
		      lock_acquire(&filesys_lock);
		      file_write_at(fte->spte->file, fte->frame,
				    fte->spte->read_bytes,
				    fte->spte->offset);
		      lock_release(&filesys_lock);
		    }
		  else
		    {
		      fte->spte->type = SWAP;
		      fte->spte->swap_index = swap_out(fte->frame);
		    }
		}
	      fte->spte->is_loaded = false;
	      list_remove(&fte->elem);
	      pagedir_clear_page(t->pagedir, fte->spte->uva);
	      palloc_free_page(fte->frame);
	      free(fte);
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
