/* Added : for mmap */
#include <stdio.h>
#include "threads/thread.h"
#include "lib/kernel/list.h"
#include "vm/page.h"

struct mmap_elem {
  int mid;                    // mapid_t
  struct sup_page_elem *spte; // corresponding spte.
  struct list_elem elem;      // for list
};

/* return minimum blank mid */
int get_mid(void);
/* add mmap_elem to current thread's mmap list */
bool add_to_mmap_list (struct sup_page_elem *spte);
void delete_mmap (int mid);
/* compare two mmap_elem according to mid */
bool mmap_less (struct mmap_elem *a, struct mmap_elem *b);
