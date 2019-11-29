#include "vm/swap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <bitmap.h>

void swap_init (void) {
  block_for_swap = block_get_role (BLOCK_SWAP);
  if (!block_for_swap) return;
  
  map_for_swap = bitmap_create(block_size(block_for_swap) / SECTORS_PER_PAGE);
  if (!map_for_swap) return;
  
  bitmap_set_all(map_for_swap, SWAP_FREE);
  lock_init(&swap_lock);
}


size_t swap_out (void *frame) {
  if (!block_for_swap || !map_for_swap)
    PANIC("Need swap partition but no swap partition present!");
  lock_acquire(&swap_lock);
  size_t empty_idx = bitmap_scan_and_flip(map_for_swap, 0, 1, SWAP_FREE);

  if (empty_idx == BITMAP_ERROR)
      PANIC("Swap partition is full!");

  size_t i;
  for (i = 0; i < SECTORS_PER_PAGE; i++)
    block_write(block_for_swap, empty_idx * SECTORS_PER_PAGE + i,
		            (uint8_t *) frame + i * BLOCK_SECTOR_SIZE);
  lock_release(&swap_lock);
  return empty_idx;
}

void swap_in (size_t used_idx, void* frame)
{
  if (!block_for_swap || !map_for_swap) return;
  lock_acquire(&swap_lock);
  if (bitmap_test(map_for_swap, used_idx) == SWAP_FREE)
    PANIC ("Trying to swap in a free block! Kernel panicking.");
  bitmap_flip(map_for_swap, used_idx);

  size_t i;
  for (i = 0; i < SECTORS_PER_PAGE; i++)
    block_read(block_for_swap, used_idx * SECTORS_PER_PAGE + i,
		           (uint8_t *) frame + i * BLOCK_SECTOR_SIZE);
  lock_release(&swap_lock);
}
