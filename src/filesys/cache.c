#include "filesys/cache.h"
#include "filesys/filesys.h"

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
  struct cache_entry *entry = cache_lookup (sector_idx);
  if (!entry) entry = cache_select_victim ();
  
  lock_acquire(entry->cache_lock);
  
  block_read (fs_device, entry->sector, &entry->cache_block);
  if (sector_ofs != 0)
    memcpy (buffer + bytes_read, &entry->cache_block + sector_ofs, chunk_size);
  entry->clock = true;
  
  lock_release(entry->cache_lock);
}

bool cache_write (block_sector_t sector_idx, void* buffer, 
                  off_t bytes_written, int chunk_size, int sector_ofs) {
  bool success = false;
  
  /* sector_idx를 buffer_head에서 검색하여 buffer에 복사 */
  /* update buffer head */
  
  return success;  
}

void cache_term () {
  /* bc_flush_all_entries함수를 호출하여 모든 buffer cache entry를 디스크로 flush */
  /* buffer cache 영역 할당 해제 */
}

struct cache_entry* cache_lookup (block_sector_t sector) { 
  /* buffe_head를 순회하며, 전달받은 sector 값과 동일한 sector 값을 갖는 buffer cache entry가 있는지 확인 */
  /* 성공: 찾은 buffer_head 반환, 실패: NULL */
}

struct cache_entry* cache_select_victim (void) {
  /* clock 알고리즘을 사용하여 victim entry를 선택 */
  /* buffer_head 전역변수를 순회하며 clock_bit 변수를 검사 */
  /* 선택된 victim entry가 dirty일 경우, 디스크로 flush */
  /* victim entry에 해당하는 buffer_head 값 update */
  /* victim entry를 return */
}  

void cache_flush_entry (struct cache_entry* p_flush_entry) {
  /* block_write 을 호출하여, 인자로 전달받은 buffer cache entry의 데이터를 디스크로 flush */
  /* buffer_head의 dirty 값 update */ 
}

void cache_flush_all_entries(void){
  /* 전역변수 buffer_head를 순회하며, dirty인 entry는 block_write 함수를 호출하여 디스크로 flush */
  /* 디스크로 flush한 후, buffer_head의 dirty 값 update */
}
