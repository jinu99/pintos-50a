#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include <stdbool.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* Added for inode_disk */
#define DIRECT_BLOCK_ENTRIES   124
#define INDIRECT_BLOCK_ENTRIES BLOCK_SECTOR_SIZE / sizeof (block_sector_t)

#define filedebug 1
#define basedebug 1

/* Added : cases of ways of pointing blocks */
enum direct_t 
  {
    NORMAL_DIRECT,
    INDIRECT,
    DOUBLE_INDIRECT,
    OUT_LIMIT         // bad case
  };

/* Added : data structure to access blocks */
struct sector_location 
  {
    enum direct_t directness;
    block_sector_t index1;
    block_sector_t index2;
  };

/* Added : data structure of indirect block */
struct inode_indirect_block
  {
    block_sector_t map_table[INDIRECT_BLOCK_ENTRIES];
  };

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                                      /* File size in bytes. */
    unsigned magic;                                    /* Magic number. */

    block_sector_t direct_table[DIRECT_BLOCK_ENTRIES]; /* Added */
    block_sector_t indirect_block;                     /* Added */
    block_sector_t double_indirect_block;              /* Added */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock extend_lock;            /* Added */
  };

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Added functions */
bool get_disk_inode (const struct inode *inode, struct inode_disk *inode_disk);
void locate_byte (off_t pos, struct sector_location *location);
off_t map_table_offset (int index);
bool register_sector (struct inode_disk *inode_disk, block_sector_t new_sector,
                 struct sector_location sec_loc);
block_sector_t byte_to_sector (struct inode_disk *inode_disk, off_t pos);
bool inode_update_file_length (struct inode_disk *inode_disk, off_t start_pos, off_t end_pos);
void free_inode_sectors (struct inode_disk* inode_disk);

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
        
      if (length > 0) {
        inode_update_file_length (disk_inode, 0, length);
      }
      cache_write (sector, disk_inode, 0, BLOCK_SECTOR_SIZE, 0);
      free (disk_inode);
      success = true;
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init (&inode->extend_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          struct inode_disk disk_inode;
          get_disk_inode (inode, &disk_inode);
          free_inode_sectors (&disk_inode);
          free_map_release (inode->sector, 1);
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  if (basedebug) printf("inode_read_at on!\n");
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  struct inode_disk disk_inode;
  get_disk_inode(inode, &disk_inode);
  
  if (filedebug) printf("\nsize = %d, offset = %d\n\n\n\n", size, offset);
  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (&disk_inode, offset);
      if (sector_idx == -1) break;
      if (filedebug) printf("\nlength = %d\n", disk_inode.length);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = disk_inode.length - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;
      if (filedebug) printf("\nmin_left = %d\n",min_left);
      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      cache_read (sector_idx, buffer, bytes_read, chunk_size, sector_ofs);
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  if (basedebug) printf("inode_read_at off!\n");
  if (filedebug) printf("\nread bytes = %d\n", bytes_read);
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  if (basedebug) printf("inode_write_at on!\n");
  if (filedebug) printf("1!!!\n");
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  if (filedebug) printf("\nsize = %d, offset = %d\n\n\n\n", size, offset);  
  if (inode->deny_write_cnt)
    return 0;
  if (filedebug) printf("2!!!\n");
  struct inode_disk disk_inode;
  if (filedebug) printf("3!!!\n");
  get_disk_inode (inode, &disk_inode);
  if (filedebug) printf("4!!!\n");
  lock_acquire (&inode->extend_lock);
  
  int old_length = disk_inode.length;
  int write_end = offset + size - 1;
  if (write_end > old_length)
    inode_update_file_length (&disk_inode, old_length, write_end);

  lock_release (&inode->extend_lock);
  if (filedebug) printf("5!!!\n");
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      if (filedebug) printf("6!!!\n");
      block_sector_t sector_idx = byte_to_sector (&disk_inode, offset);
      if (filedebug) printf("666!!!\n");
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = disk_inode.length - offset;
      if (filedebug) printf("656656!!!\n");
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
      if (filedebug) printf("7!!!\n");
      cache_write (sector_idx, buffer, bytes_written, chunk_size, sector_ofs);
      if (filedebug) printf("8!!!\n");
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  if (filedebug) printf("9!!!\n");
  cache_write (inode->sector, &disk_inode, 0, BLOCK_SECTOR_SIZE, 0);
  if (basedebug) printf("inode_write_at off!\n");
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct inode_disk inode_disk;
  cache_read (inode->sector, &inode_disk, 0, BLOCK_SECTOR_SIZE, 0);
  return inode_disk.length;
}

/* Added : get inode from buffer cache */
bool
get_disk_inode (const struct inode *inode, struct inode_disk *inode_disk)
{
  return cache_read (inode->sector, inode_disk, 0, sizeof (struct inode_disk), 0);
}

/* Added : set offset */
void
locate_byte (off_t pos, struct sector_location *location)
{
  if (basedebug) printf("locate_byte on!\n");
  off_t pos_sector = pos / BLOCK_SECTOR_SIZE;
  off_t bound1 = DIRECT_BLOCK_ENTRIES;
  off_t bound2 = bound1 + INDIRECT_BLOCK_ENTRIES;
  off_t bound3 = bound2 + INDIRECT_BLOCK_ENTRIES * INDIRECT_BLOCK_ENTRIES;

  if (pos_sector < bound1) {
    location->directness = NORMAL_DIRECT;
    location->index1 = pos_sector;
  }
  else if (pos_sector < bound2) {
    location->directness = INDIRECT;
    pos_sector -= bound1;
    location->index1 = pos_sector;
  }
  else if (pos_sector < bound3) {
    location->directness = DOUBLE_INDIRECT;
    pos_sector -= bound2;
    location->index1 = pos_sector / INDIRECT_BLOCK_ENTRIES;
    location->index2 = pos_sector % INDIRECT_BLOCK_ENTRIES;
  }
  else location->directness = OUT_LIMIT;
  if (basedebug) printf("locate_byte off!\n");
}

off_t
map_table_offset (int index) {
  return index * sizeof (block_sector_t);
}

bool
register_sector (struct inode_disk *inode_disk, block_sector_t new_sector, 
                 struct sector_location sec_loc)
{
  if (basedebug) printf("register_sector on!\n");
  struct inode_indirect_block new_block, new_ind_block;
  switch (sec_loc.directness) {
    case NORMAL_DIRECT:
      inode_disk->direct_table[sec_loc.index1] = new_sector;
      return true;
      
    case INDIRECT:
      new_block.map_table[sec_loc.index1] = new_sector;
      if (!cache_write(inode_disk->indirect_block, &new_block, 0, sizeof (struct inode_indirect_block), 0))
        return false;
      
      return true;
      
    case DOUBLE_INDIRECT:
      new_ind_block.map_table[sec_loc.index2] = new_sector;
      
      if (!cache_write(inode_disk->double_indirect_block, &new_block, 0, sizeof (struct inode_indirect_block), 0))
        return false;
      if (!cache_write(new_block.map_table[sec_loc.index1], &new_ind_block, 0, sizeof (struct inode_indirect_block), 0))
        return false;
      
      return true;
      
    case OUT_LIMIT:
      return false;
      
    default :
      NOT_REACHED ();
  }
}

block_sector_t
byte_to_sector (struct inode_disk *inode_disk, off_t pos)
{
  block_sector_t result;
  if (basedebug) printf("byte_to_sector on!\n");
  printf("len = %d pos = %d\n", inode_disk->length, pos);

  if (pos < inode_disk->length) {
    struct inode_indirect_block ind_block;
    struct sector_location sec_loc;
    locate_byte (pos, &sec_loc);

    switch (sec_loc.directness) {
      case NORMAL_DIRECT:
        printf("??????????????????????????????????????????????????????????????????\n");
        printf("??????????????????????????????????????????????????????????????????\n");
        printf("??????????????????????????????????????????????????????????????????\n");
        printf("??????????????????????????????????????????????????????????????????\n");
        printf("??????????????????????????????????????????????????????????????????\n");
        printf("??????????????????????????????????????????????????????????????????\n");
        printf("??????????????????????????????????????????????????????????????????\n");
        printf("??????????????????????????????????????????????????????????????????\n");
        printf("??????????????????????????????????????????????????????????????????\n");
        printf("??????????????????????????????????????????????????????????????????\n");
        result = inode_disk->direct_table[sec_loc.index1];
        break;

      case INDIRECT:
        printf("111111111111111111111111111111111111111111111111111111111111111111\n");
        printf("111111111111111111111111111111111111111111111111111111111111111111\n");
        printf("111111111111111111111111111111111111111111111111111111111111111111\n");
        printf("111111111111111111111111111111111111111111111111111111111111111111\n");
        printf("111111111111111111111111111111111111111111111111111111111111111111\n");
        printf("111111111111111111111111111111111111111111111111111111111111111111\n");
        printf("111111111111111111111111111111111111111111111111111111111111111111\n");
        printf("111111111111111111111111111111111111111111111111111111111111111111\n");
        printf("111111111111111111111111111111111111111111111111111111111111111111\n");
        printf("111111111111111111111111111111111111111111111111111111111111111111\n");
        if (!cache_read(inode_disk->indirect_block, &ind_block, 0, sizeof (struct inode_indirect_block), 0))
          result = -1;

        result = ind_block.map_table[sec_loc.index1];
        break;

      case DOUBLE_INDIRECT:
        printf("222222222222222222222222222222222222222222222222222222222222222222\n");
        printf("222222222222222222222222222222222222222222222222222222222222222222\n");
        printf("222222222222222222222222222222222222222222222222222222222222222222\n");
        printf("222222222222222222222222222222222222222222222222222222222222222222\n");
        printf("222222222222222222222222222222222222222222222222222222222222222222\n");
        printf("222222222222222222222222222222222222222222222222222222222222222222\n");
        printf("222222222222222222222222222222222222222222222222222222222222222222\n");
        printf("222222222222222222222222222222222222222222222222222222222222222222\n");
        printf("222222222222222222222222222222222222222222222222222222222222222222\n");
        printf("222222222222222222222222222222222222222222222222222222222222222222\n");
        if (!cache_read(inode_disk->double_indirect_block, &ind_block, 0, sizeof (struct inode_indirect_block), 0))
          result = -1;

        if (!cache_read(ind_block.map_table[sec_loc.index2], &ind_block, 0, sizeof (struct inode_indirect_block), 0))
          result = -1;

        result = ind_block.map_table[sec_loc.index1];
        break;

      case OUT_LIMIT:
        result = -1;
        break;
        
      default : 
        NOT_REACHED ();
    }
  }
  if (filedebug) printf("length in bts = 0x%08x\n", result);  
  if (basedebug) printf("byte_to_sector off!\n");
  return result;
}

bool
inode_update_file_length (struct inode_disk *inode_disk, off_t start_pos, off_t end_pos)
{
  if (basedebug) printf("inode_update_file_length on!\n");
  static uint8_t zeros[BLOCK_SECTOR_SIZE] = {0};
  inode_disk->length = end_pos - start_pos;
  int offset = (start_pos / BLOCK_SECTOR_SIZE) * BLOCK_SECTOR_SIZE;
  end_pos = (end_pos / BLOCK_SECTOR_SIZE) * BLOCK_SECTOR_SIZE;
  block_sector_t sector_ofs;
  struct sector_location sec_loc;
  printf("offset! = %d\n", offset);
  while (offset < end_pos) {
    block_sector_t sector_ofs = byte_to_sector (inode_disk, offset);
    
    if (sector_ofs == -1) {
      if (!free_map_allocate (1, &sector_ofs)) return false;
      
      locate_byte (sector_ofs, &sec_loc);
      if (!register_sector(inode_disk, sector_ofs, sec_loc)) return false;    

      cache_write(sector_ofs, zeros, 0, BLOCK_SECTOR_SIZE, 0);
    }
    offset += BLOCK_SECTOR_SIZE;
  }
  
  if (basedebug) printf("inode_update_file_length off!\n");
  return true;
}

void
free_inode_sectors (struct inode_disk* inode_disk)
{
  if (basedebug) printf("free_inode_sectors on!\n");
  struct inode_indirect_block *ind_block;
  struct inode_indirect_block *double_ind_block;
  int i, j;

  /* Double indirect 방식으로 할당된 블록 해지 */
  if (inode_disk->double_indirect_block != 0) { 
    /* 1차 인덱스 블록을 buffer cache에서 읽음*/
    i = 0;	 
    cache_read (inode_disk->double_indirect_block, ind_block, 0, sizeof (struct inode_indirect_block), 0);
    /* 1차 인덱스 블록을 통해 2차 인덱스 블록을 차례로 접근 */
    while (ind_block->map_table[i] > 0){
      /* 2차 인덱스 블록을 buffer cache에서 읽음 */ 
      j = 0;
      cache_read (ind_block->map_table[i], double_ind_block, 0, sizeof (struct inode_indirect_block), 0);
      /* 2차 인덱스 블록에 저장된 디스크 블록 번호를 접근 */
      while (double_ind_block->map_table[j] > 0) {
        /* free_map 업데이틀 통해 디스크 블록 할당 해지 */
        free_map_release(double_ind_block->map_table[j], 1);
        j++;
      }
      /* 2차 인덱스 블록 할당 해지 */
      free_map_release(ind_block->map_table[i], 1);
      i++;
    }
    /* 1차 인덱스 블록 할당 해지 */
    free_map_release (inode_disk->double_indirect_block, 1);
  }
  
  /* Indirect 방식으로 할당된 디스크 블록 해지 */
  if (inode_disk->indirect_block != 0) {
    /* 인덱스 블록을 buffer cache에서 읽음 */
    i = 0;
    cache_read (inode_disk->indirect_block, ind_block, 0, sizeof (struct inode_indirect_block), 0);
    /* 인덱스 블록에 저장된 디스크 블록 번호를 접근 */
    while (ind_block->map_table[i] > 0) {
      /* free_map 업데이트를 통해 디스크 블록 할당 해지 */
      free_map_release (ind_block->map_table[i], 1);
      i++;
    }
    free_map_release (inode_disk->indirect_block, 1);
  }

  i = 0;
  /* Direct 방식으로 할당된 디스크 블록 해지 */
  while (inode_disk->direct_table[i] > 0) {
    /* free_map 업데이트를 통해 디스크 블록 할당 해지 */
    free_map_release (inode_disk->direct_table[i], 1);
    i++;
  }
  if (basedebug) printf("free_inode_sectors off!\n");
}
