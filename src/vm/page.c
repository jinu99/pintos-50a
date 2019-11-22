#include <string.h>
#include <stdbool.h>
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

void page_table_init (struct hash *spt) {
  hash_init (spt, page_hash_function, page_less_function, NULL);
}

void page_table_destroy (struct hash *spt) {
  hash_destroy (spt, page_action_function);
}

struct sup_page_elem* get_spte (void *uva) {  
  struct sup_page_elem spte;
  spte.uva = pg_round_down(uva);

  struct hash_elem *e = hash_find(&thread_current()->spt, &spte.elem);
  if (!e) return NULL;
  return hash_entry (e, struct sup_page_elem, elem);
}

bool load_page (struct sup_page_elem *spte)
{
  bool success = false;
  //spte->pinned = true;
  if (spte->is_loaded)
    return success;
  switch (spte->type) {
    case FILE:
      success = load_file(spte);
      break;
    case SWAP:
      success = load_swap(spte);
      break;
    case MMAP:
      success = load_file(spte);
      break;
  }
  return success;
}

bool load_swap (struct sup_page_elem *spte)
{
  uint8_t *frame = frame_alloc (PAL_USER, spte);
  if (!frame) return false;
  if (!install_page(spte->uva, frame, spte->writable)) {  
    frame_free(frame);
    return false;
  }
  #ifdef DEBUGTOOL
  printf("start swap_in\n");
  #endif
  swap_in(spte->swap_index, frame);
  #ifdef DEBUGTOOL
  printf("end swap_in\n");
  #endif
  spte->is_loaded = true;
  return true;
}

bool load_file (struct sup_page_elem *spte)
{
  enum palloc_flags flags = PAL_USER;
  if (spte->read_bytes == 0)
    flags |= PAL_ZERO;
  uint8_t *frame = frame_alloc(flags, spte);
  if (!frame) return false;
  if (spte->read_bytes > 0) {
    lock_acquire(&file_lock);
    if ((int) spte->read_bytes != file_read_at(spte->file, frame,
                                               spte->read_bytes,
                                               spte->offset)) {
      lock_release(&file_lock);
      frame_free(frame);
      return false;
    }
    lock_release(&file_lock);
    memset(frame + spte->read_bytes, 0, spte->zero_bytes);
  }

  if (!install_page(spte->uva, frame, spte->writable)) {
    frame_free(frame);
    return false;
  }

  spte->is_loaded = true;  
  return true;
}

bool add_file_to_page_table (struct file *file, int32_t ofs, uint8_t *upage,
                             uint32_t read_bytes, uint32_t zero_bytes,
                             bool writable) {
  struct sup_page_elem *spte = malloc(sizeof(struct sup_page_elem));
  if (!spte) return false; 
  spte->file = file;
  spte->offset = ofs;
  spte->uva = upage;
  spte->read_bytes = read_bytes;
  spte->zero_bytes = zero_bytes;
  spte->writable = writable;
  spte->is_loaded = false;
  spte->type = FILE;
  spte->pinned = false;

  bool ret = (hash_insert(&thread_current()->spt, &spte->elem) == NULL);
  return ret;
}

bool add_mmap_to_page_table(int mid, struct file *file, int32_t ofs, uint8_t *upage,
                            uint32_t read_bytes, uint32_t zero_bytes) {
  struct sup_page_elem *spte = malloc(sizeof(struct sup_page_elem));
  if (!spte) return false;
  spte->file = file;
  spte->offset = ofs;
  spte->uva = upage;
  spte->read_bytes = read_bytes;
  spte->zero_bytes = zero_bytes;
  spte->is_loaded = false;
  spte->type = MMAP;
  spte->writable = true;
  spte->pinned = false;

  if (!add_to_mmap_table(mid, spte)) {
    free(spte);
    return false;
  }

  if (hash_insert(&thread_current()->spt, &spte->elem)) {
    return false;
  }
  return true;
}

bool expand_stack (void *uva) {
  if ((size_t)(PHYS_BASE - pg_round_down(uva)) > MAX_STACK_SIZE)
    return false;
  
  struct sup_page_elem *spte = (struct sup_page_elem *) malloc(sizeof(struct sup_page_elem));
  if (!spte) return false;
  
  spte->uva = pg_round_down(uva);
  spte->is_loaded = true;
  spte->writable = true;
  spte->type = SWAP;
  spte->pinned = true;
  
  void *frame = frame_alloc(PAL_USER, spte);
  if (!frame) { free(spte); return false; }
  
  if (!install_page(spte->uva, frame, spte->writable)) {
    frame_free(frame);
    free(spte);
    return false;
  }

  bool ret =  (hash_insert(&thread_current()->spt, &spte->elem) == NULL);
  #ifdef DEBUGTOOL
  print_page_table();
  #endif
  return ret;
}

unsigned page_hash_function (const struct hash_elem *e, void *aux UNUSED) {
  struct sup_page_elem *spte = hash_entry(e, struct sup_page_elem, elem);
  return hash_int((int) spte->uva);
}

bool page_less_function (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  struct sup_page_elem *sa = hash_entry(a, struct sup_page_elem, elem);
  struct sup_page_elem *sb = hash_entry(b, struct sup_page_elem, elem);
  if (sa->uva < sb->uva)
    return true;
  return false;
}

void page_action_function (struct hash_elem *e, void *aux UNUSED) {
  struct sup_page_elem *spte = hash_entry(e, struct sup_page_elem, elem);
  
  if (spte->is_loaded) {
    frame_free(pagedir_get_page(thread_current()->pagedir, spte->uva));
    pagedir_clear_page(thread_current()->pagedir, spte->uva);
  }
  
  free(spte);
}

void print_page_table(void){
  struct hash_iterator i;
  int n = 0;
  
  printf("=======================================================\n");
  hash_first(&i, &thread_current()->spt);
  while(hash_next(&i)){
    struct sup_page_elem *elem = hash_entry(hash_cur(&i), struct sup_page_elem, elem);
    printf("%2d: { AT 0x%x, UVA 0x%x, TYPE %s, ofs %d, is_loaded %s, pinned = %s }\n", n++, elem, elem->uva, (elem->type == FILE) ? "file" : ((elem->type == SWAP) ? "swap" : "mmap"), elem->offset, elem->is_loaded ? "yes" : "no", elem->pinned ? "yes" : "no");
  }
  printf("=======================================================\n");
}

