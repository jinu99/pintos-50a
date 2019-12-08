/*#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <list.h>
#include <stdbool.h>
#include "devices/block.h"
#include "threads/synch.h"
#include "filesys/off_t.h"

#define BUFFER_CACHE_ENTRY_NB 64

int clock_handler;

struct cache_entry {
  bool dirty;
  bool valid;
  bool clock;
  
  block_sector_t sector;
  uint8_t cache_block[BLOCK_SECTOR_SIZE];
  
  struct lock cache_lock;
};

struct cache_entry cache_list[BUFFER_CACHE_ENTRY_NB];

void cache_init ();
bool cache_read (block_sector_t, void *, off_t, int, int);
bool cache_write (block_sector_t, void *, off_t, int, int);
void cache_term ();

struct cache_entry* cache_lookup (block_sector_t);
struct cache_entry* cache_select_victim (block_sector_t);

void cache_flush_entry (struct cache_entry* p_flush_entry);
void cache_flush_all_entries ();

#endif*/

#ifndef FILESYS_BUFFER_CACHE_H
#define FILESYS_BUFFER_CACHE_H

#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/synch.h"

struct buffer_head
  {
  	// 더러운지를 나타냅니다.
    bool dirty;
    // 사용 중인지를 나타냅니다.
    bool valid;
    // 캐시된 섹터 번호입니다.
    block_sector_t address;
    // clock 알고리즘에서 사용합니다.
    bool clock;
    // 쓰기 작업을 하기 전에 이 락을 획득합니다.
    struct lock lock;
    // 데이터 버퍼를 가리킵니다.
    void *buffer;
  };

void cache_init (void);
void cache_term (void);
void cache_flush_all_entries (void);
bool cache_read (block_sector_t, void *, off_t, int, int);
bool cache_write (block_sector_t, void *, off_t, int, int);
struct buffer_head *cache_lookup (block_sector_t);
struct buffer_head *cache_select_victim (void);
void cache_flush_entry (struct buffer_head *);

#endif
