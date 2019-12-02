#include "filesys/cache.h"

void cache_init () {
  for (int i = 0; i < BUFFER_CACHE_ENTRY_NB; i++) {
    cache_list[i].dirty = false;
    cache_list[i].valid = false;
    cache_list[i].clock = false;
    lock_init(&cache_lock);
  }
}

bool cache_read (block_sector_t sector_idx, void* buffer, 
                 off_t bytes_read, int chunk_size, int sector_ofs) {
  /* sector_idx를 buffer_head에서 검색 (bc_lookup 함수 이용) */
  /* 검색결과가 없을 경우, 디스크 블록을 캐싱할 buffer entry의 buffer_head를 구함 (bc_select_victim 함수 이용) */
  /* block_read 함수를 이용해, 디스크 블록 데이터를 buffer cache로 read */
  /* memcpy 함수를 통해, buffer에 디스크 블록 데이터를 복사 */
  /* buffer_head의 clock bit을 setting */
  struct cache_entry *c = cache_lookup(sector_idx);
  if (!c){
    c = cache_select_victim();
    if (!c)
      return false;
    lock_acquire(&c->cache_lock);
    c->sector = sector_idx;
    block_read(fs_device, c->sector, &c->block);
    c->dirty = true;
    c->accessed = true;
    lock_release(&c->cache_lock);
  }
  
  /* 제작 중단 */
}

bool cache_write (block_sector_t sector_idx, void* buffer, 
                  off_t bytes_written, int chunk_size, int sector_ofs) {
  struct cache_entry *c = cache_lookup(sector_idx);
  if (!c)
    c =  cache_select_victim();
  if (!c)
    return false;
  lock_acquire(&c->cache_lock);
  memcpy((uint8_t*) sector_idx + sector_ofs, buffer + bytes_written, chunk_size);
  lock_release(&c->cache_lock);
  return true;  
}

void cache_term () {
  cache_flush_all_entries ();
}

struct cache_entry* cache_lookup (block_sector_t sector) { 
  struct cache_entry *c;
  for (int i = 0; i < BUFFER_CACHE_ENTRY_NB; i++){
    c = &(cache_list[i]);
    if (c->sector == sector)
      return c;
  }
  return NULL;
}

struct cache_entry* cache_select_victim (void) {
  /* clock 알고리즘을 사용하여 victim entry를 선택 */
  /* buffer_head 전역변수를 순회하며 clock_bit 변수를 검사 */
  /* 선택된 victim entry가 dirty일 경우, 디스크로 flush */
  /* victim entry에 해당하는 buffer_head 값 update */
  /* victim entry를 return */
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

void cache_flush_all_entries(void){
  struct cache_entry *c;
  for (int i = 0; i < BUFFER_CACHE_ENTRY_NB; i++){
    c = &(cache_list[i]);
    if (!c->valid) continue;
    lock_acquire(&c->cache_lock);
    /* If dirty bit is true, then save changed to the disk. */
    if (c->dirty){
      block_write(fs_device, c->sector, &c->cache_block);
      c->dirty = false;
    }    
    lock_release(&c->cache_lock);
  }
}
