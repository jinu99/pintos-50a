/*#include <stdio.h>
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
 
  if (!entry) { 
    if (cache_debug) printf("victim!\n"); 
    entry = cache_select_victim (sector_idx); 
    block_read (fs_device, sector_idx, entry->cache_block); 
  } 
  if (!entry) return false;
  
  if (cache_debug) printf("read on!\n");
  
  lock_acquire(&entry->cache_lock);
  
  //block_read (fs_device, entry->sector, &entry->cache_block);
  if (cache_debug) printf("???????!! bf = 0x%08x, bytes = 0x%08x, cb = 0x%08x \n\n", buffer, bytes_read, entry->cache_block);
  memcpy (buffer + bytes_read, entry->cache_block + sector_ofs, chunk_size);
  printf("len -> 0x%02x%02x%02x%02x, table[0] -> 0x%02x%02x%02x%02x\n", entry->cache_block[3], entry->cache_block[2], entry->cache_block[1], entry->cache_block[0], entry->cache_block[11], entry->cache_block[10], entry->cache_block[9], entry->cache_block[8]);
  if (cache_debug) printf("?????????????????????????????\n\n\n");
  entry->clock = true;
  
  lock_release(&entry->cache_lock);
  
  if (cache_debug) print_cache_list();
  if (cache_debug) printf("read off!\n");
  cache_flush_all_entries ();
  return true;
}

bool cache_write (block_sector_t sector_idx, void* buffer, 
                  off_t bytes_written, int chunk_size, int sector_ofs) {
  struct cache_entry *entry = cache_lookup(sector_idx);
  
  if (!entry) { 
    if (cache_debug) printf("victim!\n"); 
    entry = cache_select_victim (sector_idx); 
    block_read (fs_device, sector_idx, entry->cache_block); 
  }
    
  if (!entry) return false;
  
  if (cache_debug) printf("write on!\n");
  
  if (cache_debug) print_cache_list();
  
  lock_acquire(&entry->cache_lock);
  
  memcpy(entry->cache_block + sector_ofs, buffer + bytes_written, chunk_size);
  entry->clock = true;
  entry->dirty = true;
  
  lock_release(&entry->cache_lock);
  
  if (cache_debug) print_cache_list();

  if (cache_debug) printf("write off!\n");
  cache_flush_all_entries ();
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
      block_write(fs_device, p_flush_entry->sector, p_flush_entry->cache_block);
      p_flush_entry->dirty = false;
    }
    
    lock_release(&p_flush_entry->cache_lock);
  }
}

void cache_flush_all_entries () {
  for (int i = 0; i < BUFFER_CACHE_ENTRY_NB; i++)
    cache_flush_entry(&(cache_list[i]));
  if (cache_debug) print_cache_list();
}

void print_cache_list() {
  printf("==============================================================\n");
  for (int i = 0; i < BUFFER_CACHE_ENTRY_NB; i++) {
    if (cache_list[i].valid)
      printf("{ cache %d : dirty %s, clock %s, sector %d, len 0x%02x%02x%02x%02x, magic %c%c%c%c table[0] 0x%02x%02x%02x%02x }\n", i, cache_list[i].dirty ? "true" : "false", cache_list[i].clock ? "true" : "false", cache_list[i].sector, cache_list[i].cache_block[3], cache_list[i].cache_block[2], cache_list[i].cache_block[1], cache_list[i].cache_block[0], cache_list[i].cache_block[7], cache_list[i].cache_block[6], cache_list[i].cache_block[5], cache_list[i].cache_block[4],  cache_list[i].cache_block[11], cache_list[i].cache_block[10], cache_list[i].cache_block[9], cache_list[i].cache_block[8]); }
  printf("==============================================================\n");
}*/

#include "filesys/cache.h"
#include "threads/palloc.h"
#include <string.h>
#include <debug.h>

// 캐시할 블록의 수
#define BUFFER_CACHE_ENTRIES 64

// 실제 데이터를 제외한, 캐시 스스로에 대한 설명을 가지고 있습니다.
static struct buffer_head buffer_head[BUFFER_CACHE_ENTRIES];

// 실제 데이터가 저장되는 버퍼입니다.
static char p_buffer_cache[BUFFER_CACHE_ENTRIES * BLOCK_SECTOR_SIZE];

// clock 알고리즘을 위한 시계 바늘입니다.
static struct buffer_head *clock_hand;

// buffer_head 배열에 새로운 값을 추가하거나 뺄 때 중간 과정을 보이지 않게 하는 락입니다.
static struct lock cache_lock;

static void init_head (struct buffer_head *, void *);

// 버퍼 캐시 시스템을 초기화합니다.
void
cache_init (void)
{
  // 바로 위에서 설명한 자료 구조를 각각 초기화합니다.
  struct buffer_head *head;
  void *cache = p_buffer_cache;
  for (head = buffer_head;
       head != buffer_head + BUFFER_CACHE_ENTRIES;
       head++, cache += BLOCK_SECTOR_SIZE)
    init_head (head, cache);
  clock_hand = buffer_head;
  lock_init (&cache_lock);
}

// 하나의 buffer_head를, 주어지는 버퍼를 가리키도록 하여 초기화합니다.
static void
init_head (struct buffer_head *head, void *buffer)
{
  // 더럽지 않고, 아직 유효하지 않은 상태로 초기화합니다.
  memset (head, 0, sizeof (struct buffer_head));
  lock_init (&head->lock);
  head->buffer = buffer;
}

void cache_term (void) { cache_flush_all_entries (); }

// 버퍼 캐시 시스템을 종료합니다.
void
cache_flush_all_entries (void)
{
  struct buffer_head *head;
  for (head = buffer_head;
       head != buffer_head + BUFFER_CACHE_ENTRIES; head++)
    {
      // 아직 쓰지 않은 모든 더러운 캐시를 써서 정리합니다.
      lock_acquire (&head->lock);
      cache_flush_entry (head);
      lock_release (&head->lock);
    }
}

// 버퍼를 이용하여 읽기 작업을 수행합니다.
bool
cache_read (block_sector_t address, void *buffer,
         off_t offset, int chunk_size, int sector_ofs)
{
  struct buffer_head *head;
  if (!(head = cache_lookup (address)))
    {
      // 여기에 도달하였다면 버퍼에 섹터가 없습니다.
      head = cache_select_victim ();
      // head에 캐시에서 제거할 섹터가 있습니다.
      cache_flush_entry (head);
      head->valid = true;
      head->dirty = false;
      head->address = address;
      // address를 지정하였으므로 락을 해제합니다.
      lock_release (&cache_lock);
      // 실제 읽기 작업
      block_read (fs_device, address, head->buffer);
    }
  head->clock = true;
  // 버퍼에서 읽기 작업
  memcpy (buffer + offset, head->buffer + sector_ofs, chunk_size);
  lock_release (&head->lock);
  return true;
}

// 버퍼를 이용하여 읽기 작업을 수행합니다.
bool
cache_write (block_sector_t address, void *buffer,
         off_t offset, int chunk_size, int sector_ofs)
{
  struct buffer_head *head;
  if (!(head = cache_lookup (address)))
    {
      // 여기에 도달하였다면 버퍼에 섹터가 없습니다.
      head = cache_select_victim ();
      // head에 캐시에서 제거할 섹터가 있습니다.
      cache_flush_entry (head);
      head->valid = true;
      head->address = address;
      // address를 지정하였으므로 락을 해제합니다.
      lock_release (&cache_lock);
      // 실제 읽기 작업
      block_read (fs_device, address, head->buffer);
    }
  head->clock = true;
  // 곧 이 버퍼는 더러워집니다.
  head->dirty = true;
  // 버퍼에서 쓰기 작업
  memcpy (head->buffer + sector_ofs, buffer + offset, chunk_size);
  lock_release (&head->lock);
  return true;
}

struct buffer_head *
cache_lookup (block_sector_t address)
{
  // 버퍼에서 항목을 제거하는 작업의 중간 과정이 보이지 않도록 해야 합니다.
  // 락을 걸지 않으면 한 섹터에 대한 캐시가 여러 개 만들어질 수 있습니다.
  lock_acquire (&cache_lock);
  struct buffer_head *head;
  for (head = buffer_head;
       head != buffer_head + BUFFER_CACHE_ENTRIES; head++)
    {
      if (head->valid && head->address == address)
        {
          // 캐시 적중 상황입니다.
          // 데이터에 접근하기 전에 더 구체적인 락을 획득하고,
          lock_acquire (&head->lock);
          // 처음에 잠근 락을 해제합니다.
          lock_release (&cache_lock);
          return head;
        }
    }
  // 캐시 미스 상황입니다. 이 상황을 유지하기 위해서
  // 처음에 잠근 락이 걸린 상태로 반환합니다.
  return NULL;
}

// clock 알고리즘으로 교체할 캐시를 선택합니다.
struct buffer_head *
cache_select_victim (void)
{
  // 이 루프는 최대 두 번 수행됩니다.
  for (;;)
    {
      for (;
           clock_hand != buffer_head + BUFFER_CACHE_ENTRIES;
           clock_hand++)
        {
          lock_acquire (&clock_hand->lock);
          if (!clock_hand->valid || !clock_hand->clock)
            {
              return clock_hand++;
            }
          clock_hand->clock = false;
          lock_release (&clock_hand->lock);   
        }
      clock_hand = buffer_head;
    }
  NOT_REACHRED ();
}

// 주어진 엔트리가 사용 중인 엔트리이고 더러운 경우에
// 버퍼를 실제로 쓰고, 상태를 깨끗하게 만듭니다.
void
cache_flush_entry (struct buffer_head *entry)
{
  ASSERT (lock_held_by_current_thread (&entry->lock));
  if (!entry->valid || !entry->dirty)
    return;
  entry->dirty = false;
  block_write (fs_device, entry->address, entry->buffer);
}

