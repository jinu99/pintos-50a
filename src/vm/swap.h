#ifndef __VM_SWAP_H
#define __VM_SWAP_H

#include "devices/block.h"
#include "threads/synch.h"
#include <bitmap.h>

#define SWAP_FREE 0
#define SWAP_IN_USE 1

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

struct lock swap_lock;
struct block *swap_block;
struct bitmap *swap_map;

void swap_init(size_tused_index, void* kaddr);
void swap_in(size_tused_index, void* kaddr);
size_t swap_out(void* kaddr);

#endif /* vm/page.h */
