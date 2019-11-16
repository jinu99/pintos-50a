#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "vm/frame.h"

#define FILE 0
#define SWAP 1
#define MMAP 2
#define HASH_ERROR 3

#define MAX_STACK_SIZE (1 << 23) // 8MB

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

void page_table_init (struct hash *spt);
void page_table_destroy (struct hash *spt);

bool load_page (struct sup_page_elem *spte);
bool load_mmap (struct sup_page_elem *spte);
bool load_swap (struct sup_page_elem *spte);
bool load_file (struct sup_page_elem *spte);
bool add_file_to_page_table (struct file *file, int32_t ofs, uint8_t *upage,
                             uint32_t read_bytes, uint32_t zero_bytes,
                             bool writable);
bool add_mmap_to_page_table(struct file *file, int32_t ofs, uint8_t *upage,
                            uint32_t read_bytes, uint32_t zero_bytes);
bool expand_stack (void *uva);
struct sup_page_elem* get_spte (void *uva);

unsigned page_hash_function (const struct hash_elem *e, void *aux UNUSED);
bool page_less_function (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
void page_action_function (struct hash_elem *e, void *aux UNUSED);
void print_page_table(void);

#endif /* vm/page.h */
