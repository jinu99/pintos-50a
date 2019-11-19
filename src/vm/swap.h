#ifndef __VM_SWAP_H
#define __VM_SWAP_H

#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <bitmap.h>

#define SWAP_FREE 0
#define SWAP_IN_USE 1

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

struct lock swap_lock;
struct block *swap_block;
struct bitmap *swap_map;

void swap_init(void);
void swap_in(size_t used_index, void* frame);
size_t swap_out(void* frame);

#endif /* vm/page.h */
