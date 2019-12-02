#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <list.h>
#include <stdbool.h>
#include "devices/block.h"

#define BUFFER_CACHE_ENTRY_NB 64

int clock_handler;

struct cache_entry {
  bool dirty;
  bool valid;
  bool clock;
  
  block_sector_t sector;
  uint8_t cache_block[BLOCK_SECTOR_SIZE];
  
  struct lock cache_lock;
}

struct cache_entry cache_list[BUFFER_CACHE_ENTRY_NB];

void cache_init ();
bool cache_read (block_sector_t, void *, off_t, int, int);
bool cache_write (block_sector_t, void *, off_t, int, int);
void cache_term ();

struct cache_entry* cache_lookup (block_sector_t);
struct cache_entry* cache_select_victim ();

void cache_flush_entry (struct cache_entry* p_flush_entry);
void cache_flush_all_entries ();

#endif
