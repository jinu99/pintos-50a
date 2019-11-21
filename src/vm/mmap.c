#include <stdio.h>
#include "vm/mmap.h"
#include "threads/thread.h"
#include "lib/kernel/list.h"
#include "vm/page.h"


int get_mid(){
  int val = 1;
  struct list mmap_table = thread_current()->mmap_table;
  struct list_elem *e;
  struct mmap_elem *m;
  
  for (e = list_begin(&mmap_table); e != list_end(&mmap_table); e = list_next(e)){
    m = list_entry(e, struct mmap_elem, elem);
    if (val < m->mid){
      val++;
      if (val < m->mid) break;
    }
  }
  return val;
}

bool add_to_mmap_list (struct sup_page_elem *spte) {
  struct mmap_elem *m = malloc(sizeof(struct mmap_elem));
  if (!m) return false;
  m->spte = spte;
  m->mid = get_mid();
  list_insert_ordered(&thread_current()->mmap_table, &m->elem, mmap_less, NULL);
  return true;
}

bool mmap_less (struct mmap_elem *a, struct mmap_elem *b) {
  return a->mid < b->mid;
}
