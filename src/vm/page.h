#ifndef __VM_PAGE_H
#define __VM_PAGE_H

#include <hash.h>
#include "vm/frame.h"

#define FILE 0
#define SWAP 1
#define MMAP 2
#define HASH_ERROR 3

#define STACK_GROW_MAX (1 << 23) // 8MB

struct sup_page_elem {
	uint8_t type;
	void *uva;
	bool writable;

	bool is_loaded;
	bool pinned;

	// For files
	struct file *file;
	size_t offset;
	size_t read_bytes;
	size_t zero_bytes;
  
	// For swap
	size_t swap_index;
  
	struct hash_elem elem;
};

void page_table_init (struct hash*);
void page_table_destroy (struct hash*);
struct sup_page_elem* get_spte (void*);

bool lazy_load (struct sup_page_elem*);
bool from_file (struct sup_page_elem*);
bool from_swap (struct sup_page_elem*);

bool locate_file_to_table (struct file*, int32_t, uint8_t*,
                           uint32_t, uint32_t, bool);
bool locate_mmap_to_table(int, struct file*, int32_t, uint8_t*,
                          uint32_t, uint32_t);
bool expand_stack (void*);

unsigned page_hash_function (const struct hash_elem*, void*);
bool page_less_function (const struct hash_elem*, const struct hash_elem*, void*);
void page_action_function (struct hash_elem*, void*);
void print_page_table(void);

#endif /* vm/page.h */
