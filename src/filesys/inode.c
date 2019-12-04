#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* Added for inode_disk */
#define DIRECT_BLOCK_ENTRIES   123
#define INDIRECT_BLOCK_ENTRIES BLOCK_SECTOR_SIZE / sizeof (block_sector_t)

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

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length)
    return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

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
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      if (free_map_allocate (sectors, &disk_inode->start)) 
        {
          block_write (fs_device, sector, disk_inode);
          if (sectors > 0) 
            {
              static char zeros[BLOCK_SECTOR_SIZE];
              size_t i;
              
              for (i = 0; i < sectors; i++) 
                block_write (fs_device, disk_inode->start + i, zeros);
            }
          success = true; 
        } 
      free (disk_inode);
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
  block_read (fs_device, inode->sector, &inode->data);
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
          free_map_release (inode->sector, 1);
          free_map_release (inode->data.start,
                            bytes_to_sectors (inode->data.length)); 
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
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  
  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

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
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      cache_write (sector_idx, buffer, bytes_written, chunk_size, sector_ofs);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

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
  return inode->data.length;
}

/* Added : get inode from buffer cache */
bool
get_disk_inode (const struct inode *inode, struct inode_disk *inode_disk)
{
  return cache_read (inode->sector, inode_disk, 0,
                     sizeof (struct inode_disk), 0);
}

/* Added : set offset */
void
locate_byte (off_t pos, struct sector_location *location)
{
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
}

off_t
map_table_offset (int index) {
  return index * sizeof (block_sector_t);
}

bool
register_sector (struct inode_disk *inode_disk, block_sector_t new_sector, 
                 struct sector_location sec_loc)
{
  struct inode_indirect_block new_block, new_ind_block;
  
  switch (sec_loc.directness) {
    case NORMAL_DIRECT:
      inode_disk->direct_table[sec_loc.index1] = new_sector;
      return true;
      
    case INDIRECT:
      new_block = (struct inode_indirect_block *) malloc (BLOCK_SECTOR_SIZE);
      if (!new_block) return false;
      
      new_block.map_table[sec_loc.index1] = new_sector;
      if (!cache_write(inode_disk->indirect_block, &new_block, 0, sizeof (struct inode_indirect_block), 0))
        return false;
      
      free (new_block);
      return true;
      
    case DOUBLE_INDIRECT:
      new_block = (struct inode_indirect_block *) malloc (BLOCK_SECTOR_SIZE);
      if (!new_block) return false;
      
      new_ind_block = (struct inode_indirect_block *) malloc (BLOCK_SECTOR_SIZE);
      if (!new_ind_block) return false;
      
      new_ind_block.map_table[sec_loc.index2] = new_sector;
      
      if (!cache_write(inode_disk->double_indirect_block, &new_block, 0, sizeof (struct inode_indirect_block), 0))
        return false;
      if (!cache_write(new_block.map_table[sec_loc.index1], &new_ind_block, 0, sizeof (struct inode_indirect_block), 0))
        return false;
      
      free (new_block);
      free (new_ind_block);
      return true;
      
    case OUT_LIMIT:
      return false;
      
    default :
      NOT_REACHED ();
  }

block_sector_t
byte_to_sector (struct inode_disk *inode_disk, off_t pos)
{
  block_sector_t result;

  if (pos < inode_disk->length) {
    struct inode_indirect_block *ind_block;
    struct sector_location sec_loc;
    locate_byte (pos, &sec_loc);

    switch (sec_loc.directness) {
      case NORMAL_DIRECT:
        result = inode_disk->direct_map_table[sec_loc.index1];
        break;

      case INDIRECT:
        ind_block = (struct inode_indirect_block *) malloc (BLOCK_SECTOR_SIZE);
        if (!ind_block) result = -1;
        
        if (!cache_read(inode_disk->indirect_block, &ind_block, 0, sizeof (struct inode_indirect_block), 0))
          result = -1;

        result = ind_block.map_table[sec_loc.index1];
        free (ind_block);
        break;

      case DOUBLE_INDIRECT:
        ind_block = (struct inode_indirect_block *) malloc (BLOCK_SECTOR_SIZE);
        if (!ind_block) result = -1;

        if (!cache_read(inode_disk->double_indirect_block, &ind_block, 0, sizeof (struct inode_indirect_block), 0))
          result = -1;

        if (!cache_read(ind_block.map_table[sec_loc.index2], &ind_block, 0, sizeof (struct inode_indirect_block), 0))
          result = -1;

        result = ind_block.map_table[sec_loc.index1];
        free (ind_block);
        break;

      case OUT_LIMIT:
        result = -1;
        break;
        
      default : 
        NOT_REACHED ();
    }
  }
  
  return result;
}

bool
inode_update_file_length (struct inode_disk* inode_disk, off_t start_pos, off_t end_pos)
{
  static uint8_t zeros[BLOCK_SECTOR_SIZE];
  int len = inode_disk->length;
  int new_len = end_pos - start_pos;
  int size = new_len - len;
  
  /* 블록 단위로 loop을 수행하며 새로운 디스크 블록 할당 */
  while (size > 0) {
    /* 디스크 블록 내 오프셋 계산 */
    block_sector_t sector_ofs = byte_to_sector (inode_disk, length);
    
    if (sector_ofs > 0) {
      /* 블록 오프셋이 0보다 클 경우, 이미 할당된 블록 */
    }
    else {
      /* 새로운 디스크 블록을 할당 */
      
      if (free_map_allocate(1, &sector_idx)) {
        /* inode_disk에 새로 할당받은 디스크 블록 번호 업데이트 */ 
      }
      else {
        free(zeroes);
        return false;
      }
      /* 새로운 디스크 블록을 0으로 초기화 */
      bc_write(sector_idx, zeroes, 0, BLOCK_SECTOR_SIZE, 0);
    }
    /* Advance. */ 
    size -= chunk_size;
    offset += chunk_size;
  }
  
  free(zeroes);
  return true;
}

void
free_inode_sectors (struct inode_disk* inode_disk)
{
  /* Double indirect 방식으로 할당된 블록 해지 */
  if (inode_disk->double_indirect_block_sec > 0) { 
    /* 1차 인덱스 블록을 buffer cache에서 읽음*/
    i = 0;
    /* 1차 인덱스 블록을 통해 2차 인덱스 블록을 차례로 접근 */
    while (ind_block_1->map_table[i] > 0){
      /* 2차 인덱스 블록을 buffer cache에서 읽음 */ 
      j = 0;
      /* 2차 인덱스 블록에 저장된 디스크 블록 번호를 접근 */
      while (ind_block_2->map_table[j] > 0) {
        /* free_map 업데이틀 통해 디스크 블록 할당 해지 */
        j++;
      }
      /* 2차 인덱스 블록 할당 해지 */
      i++;
    }
    /* 1차 인덱스 블록 할당 해지 */
    ...
  }
  
  /* Indirect 방식으로 할당된 디스크 블록 해지 */
  if (inode_disk->indirect_block_sec > 0){
    ...
    /* 인덱스 블록을 buffer cache에서 읽음 */
    /* 인덱스 블록에 저장된 디스크 블록 번호를 접근 */
    while (ind_block->map_table[i] > 0) {
      /* free_map 업데이트를 통해 디스크블록 할당 해지 */
      i++;
    }
    ...
    /* Direct 방식으로 할당된 디스크 블록 해지 */
      while (inode_disk->direct_map_table[i] > 0) {
        /* free_map업데이트를통해디스크블록할당해지*/
      i++;
    }
  }
}





