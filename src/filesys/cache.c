#include <stdio.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"

#define cache_debug 1

void cache_init () {
  for (int i = 0; i < BUFFER_CACHE_ENTRY_NB; i++) {
    cache_list[i].dirty = false;
    cache_list[i].valid = false;
    cache_list[i].clock = false;
    lock_init(&cache_list[i].cache_lock);
  }
  clock_handler = 0;
}

bool cache_read (block_sector_t sector_idx, void* buffer, 
                 off_t bytes_read, int chunk_size, int sector_ofs) {
  struct cache_entry *entry = cache_lookup (sector_idx);
  if (!entry) { printf("victim!\n"); entry = cache_select_victim (sector_idx); block_read (fs_device, entry->sector, &entry->cache_block); }
  if (!entry) return false;
  
  if (cache_debug) printf("read on!\n");
  
  if (cache_debug)print_cache_list();
  
  lock_acquire(&entry->cache_lock);
  
  //block_read (fs_device, entry->sector, &entry->cache_block);
  memcpy (buffer + bytes_read, &entry->cache_block + sector_ofs, chunk_size);
  entry->clock = true;
  
  lock_release(&entry->cache_lock);
  
  if (cache_debug) printf("read off!\n");
  return true;
}

bool cache_write (block_sector_t sector_idx, void* buffer, 
                  off_t bytes_written, int chunk_size, int sector_ofs) {
  struct cache_entry *entry = cache_lookup(sector_idx);
  if (!entry) { printf("victim!\n"); entry = cache_select_victim (sector_idx); block_read (fs_device, entry->sector, &entry->cache_block); }
  if (!entry) return false;
  
  if (cache_debug) printf("write on!\n");
  
  if (cache_debug) print_cache_list();
  
  lock_acquire(&entry->cache_lock);
  
  memcpy(&entry->cache_block + sector_ofs, buffer + bytes_written, chunk_size);
  entry->clock = true;
  entry->dirty = true;
  
  lock_release(&entry->cache_lock);
  
  if (cache_debug) printf("write off!\n");
  return true;
}

void cache_term () {
  cache_flush_all_entries ();
}

struct cache_entry* cache_lookup (block_sector_t sector) { 
  struct cache_entry *entry;
  
  for (int i = 0; i < BUFFER_CACHE_ENTRY_NB; i++){
    entry = &(cache_list[i]);
    
    if (entry->sector == sector)
      return entry;
  }
  
  return NULL;
}

struct cache_entry* cache_select_victim (block_sector_t sector) {
  struct cache_entry* entry;
  
  while (true) {
    if (clock_handler >= BUFFER_CACHE_ENTRY_NB) clock_handler = 0;
    
    entry = &(cache_list[clock_handler]);
    if (!entry->valid) break;
    
    if (entry->clock) entry->clock = false; 
    else break;
    
    clock_handler++;
  }
  
  cache_flush_entry(entry);
  
  entry->valid = true;
  entry->dirty = false;
  entry->sector = sector;
  //print_cache_list();
  return entry;
}  

void cache_flush_entry (struct cache_entry* p_flush_entry) {
  if (p_flush_entry){
    lock_acquire(&p_flush_entry->cache_lock);
    
    if (p_flush_entry->valid && p_flush_entry->dirty){
      block_write(fs_device, p_flush_entry->sector, &p_flush_entry->cache_block);
      p_flush_entry->dirty = false;
    }
    
    lock_release(&p_flush_entry->cache_lock);
  }
}

void cache_flush_all_entries () {
  for (int i = 0; i < BUFFER_CACHE_ENTRY_NB; i++)
    cache_flush_entry(&(cache_list[i]));
}

void print_cache_list() {
  printf("==============================================================\n");
  for (int i = 0; i < BUFFER_CACHE_ENTRY_NB; i++) {
    if (cache_list[i].valid)
      printf("{ cache %d : dirty %s, clock %s, sector %d }\n", i, cache_list[i].dirty ? "true" : "false", cache_list[i].clock ? "true" : "false", cache_list[i].sector); }
  printf("==============================================================\n");
}


