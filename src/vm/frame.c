#include "filesys/file.h"
#include <stdio.h>
#include <stdbool.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "lib/kernel/hash.h"

void frame_table_init (void) {
  hash_init(&frame_table, frame_hash_function, frame_less_function, NULL);
  lock_init(&frame_lock);
}

void* frame_alloc (enum palloc_flags flags, struct sup_page_elem *spte) {
  if ((flags & PAL_USER) == 0)
    return NULL;
      
  void *frame = palloc_get_page(flags);
  #ifdef DEBUGTOOL
  printf("alloc! \n");
  #endif
  if (frame)
    frame_add_to_table(frame, spte);    
  else {
    frame = frame_evict(flags);
    if (!frame)
      PANIC ("Frame could not be evicted because swap is full!");
      
    frame_add_to_table(frame, spte); 
  }

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

void* frame_evict (enum palloc_flags flags) {
  struct hash_iterator i, j;
  bool pin_check = false;
  lock_acquire(&frame_lock);
  
  #ifdef DEBUGTOOL
  printf("evict!\n");
  #endif

  hash_first (&i, &frame_table);
  hash_next (&i);
  while (true) {
    #ifdef DEBUGTOOL
    printf("1 evict!\n");
    #endif
    struct frame_table_elem *elem = hash_entry(hash_cur(&i), struct frame_table_elem, frame_elem);
    #ifdef DEBUGTOOL
    printf("0x%08x\n", elem->spte);
    #endif
    
    if (!(elem->spte)) {
      #ifdef DEBUGTOOL
      printf("1.5 evict!\n");
      #endif
      hash_next(&i);
      if (!(i.elem)) { 
        if (!pin_check)  { lock_release(&frame_lock); return NULL; }
        hash_first (&i, &frame_table); hash_next (&i); }
      continue;
    }
    
    if (!elem->spte->pinned) {
      pin_check = true;
      #ifdef DEBUGTOOL
      printf("2 evict!\n");
      #endif
	    struct thread *t = elem->holder;
	    if (pagedir_is_accessed(t->pagedir, elem->spte->uva)) {
	      #ifdef DEBUGTOOL
        printf("3 evict!\n");
        #endif
	      pagedir_set_accessed(t->pagedir, elem->spte->uva, false);
	      }
	      
	    else {
	      #ifdef DEBUGTOOL
        printf("4 evict!\n");
        #endif
	      if (true || pagedir_is_dirty(t->pagedir, elem->spte->uva) || elem->spte->type == SWAP) {
	        elem->spte->type = SWAP;
          elem->spte->swap_index = swap_out(elem->frame); 
		    }
		    #ifdef DEBUGTOOL
        printf("5 evict!\n");
        #endif
	      elem->spte->is_loaded = false;
	      list_remove(&elem->frame_elem);
	      pagedir_clear_page(t->pagedir, elem->spte->uva);
	      palloc_free_page(elem->frame);
	      free(elem);
	      void* ret = palloc_get_page(flags);
	      lock_release(&frame_lock);
	      #ifdef DEBUGTOOL
        printf("6 evict!\n");
        #endif
	      return ret;
	    }
	  }
	  #ifdef DEBUGTOOL
    printf("7 evict!\n");
    #endif
    hash_next(&i);
    if (!(i.elem)) { 
      if (!pin_check) { lock_release(&frame_lock); return NULL; }
      hash_first (&i, &frame_table); hash_next (&i); }
  }
  #ifdef DEBUGTOOL
  printf("evict done!\n");
  #endif
}

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
    printf("%2d: { Thread %s, VA 0x%x, SPTE 0x%x, addr 0x%08x }\n", n++, elem->holder->name, elem->frame, elem->spte, elem);
  }
  printf("=======================================================\n");
  lock_release(&frame_lock);
}
