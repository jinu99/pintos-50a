#include <stdio.h>
#include "vm/mmap.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "lib/kernel/list.h"
#include "lib/kernel/hash.h"
#include "vm/page.h"


int get_mid(){
  int val = 1;
  struct list *mmap_table = &thread_current()->mmap_table;
  struct list_elem *e;
  struct mmap_elem *m;
  for (e = list_begin(mmap_table); e != list_end(mmap_table); e = list_next(e)){
    m = list_entry(e, struct mmap_elem, elem);
    if (val < m->mid){
      val++;
      if (val < m->mid) break;
    }
  }
  return val;
}

bool add_to_mmap_table (int mid, struct sup_page_elem *spte) {
  struct mmap_elem *m = malloc(sizeof(struct mmap_elem));
  if (!m) return false;
  m->spte = spte;
  m->mid = mid;
  list_insert_ordered(&thread_current()->mmap_table, &m->elem, mmap_less, NULL);
  return true;
}

void delete_mmap_at_mid (int mid){
  struct thread *cur = thread_current();
  struct list_elem *e, *next;
  struct mmap_elem *m;
  struct file *closing_file;
  
  e = list_begin(&cur->mmap_table);
  while(e != list_end(&cur->mmap_table)){
    next = list_next(e);
    m = list_entry(e, struct mmap_elem, elem);
    if (m->mid == mid){
      m->spte->pinned = true;
      /* if contents are changed, save it to file. otherwise, just free */
      if (m->spte->is_loaded){
        if (pagedir_is_dirty(cur->pagedir, m->spte->uva)){
          /* save changed to origin file */
          lock_acquire(&file_lock);
          file_write_at(m->spte->file, m->spte->uva, m->spte->read_bytes, m->spte->offset);
          lock_release(&file_lock);
        }
        frame_free(pagedir_get_page(cur->pagedir, m->spte->uva));
        pagedir_clear_page(cur->pagedir, m->spte->uva);
      }
      /* remove spte from page table */
      hash_delete(&cur->spt, &m->spte->elem);
      /* remove mmap_elem from mmap table */
      list_remove(&m->elem);

      closing_file = m->spte->file;
      free(m->spte);
      free(m);
    }
    e = next;
  }
  if (closing_file){
    lock_acquire(&file_lock);
    file_close(closing_file);
    lock_release(&file_lock);
  }
}

void print_mmap_table (){
  struct list_elem *e;
  struct thread *cur = thread_current();
  struct mmap_elem *m;
  int cnt = 0;
  
  printf("=======================================================\n");
  for(e = list_begin(&cur->mmap_table); e != list_end(&cur->mmap_table); e = list_next(e)){
    m = list_entry(e, struct mmap_elem, elem);
    printf("%2d: { MMAP ID %d, SPTE 0x%x }\n", cnt++, m->mid, m->spte);
  }
  printf("=======================================================\n");
}

bool mmap_less (struct mmap_elem *a, struct mmap_elem *b) {
  return a->mid < b->mid;
}
