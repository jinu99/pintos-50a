#include "userprog/syscall.h"
#include <stdio.h>
#include "lib/user/syscall.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/fd.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "filesys/inode.h"
#include "filesys/file.h"

#define SYSDEBUG 0

static void syscall_handler (struct intr_frame *);
/* Added: check each arguments are valid, and terminate the process if
   the arguments are invalid. */
bool is_valid_ptr (void * ptr, void *esp);
bool is_valid_string (void * ptr, void * esp);
bool is_valid_buffer (void * ptr, void * esp, size_t size, bool be_write);
void setpin_ptr(void * ptr, bool pin);
void setpin_string (void * ptr, bool pin);
void setpin_buffer (void * ptr, size_t size, bool pin);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* Check whether esp is valid */
  if (SYSDEBUG) printf("1\n");
  if (!is_valid_ptr((uint32_t *)f->esp, f->esp))
    sys_exit(-1, f); 
  if (SYSDEBUG) printf("1\n");
  /* Added: handle each syscalls */
  uint32_t *cur_esp = (uint32_t *)f->esp;
  
  struct file *fp;
  int fd, i, len;
  char *buf;
  char inp;
  
  //hex_dump(cur_esp, cur_esp, 100, true);
  switch (*cur_esp)
  {
    case SYS_HALT:
      if (SYSDEBUG) printf("halt!\n");
      shutdown_power_off();
      NOT_REACHED();
      break; 
      
    case SYS_EXIT:
      if (SYSDEBUG) printf("exit!\n");
      if (!is_user_vaddr(cur_esp + 1))
        sys_exit(-1, f);
        
      sys_exit((int)*(cur_esp + 1), f);
      break;
      
    case SYS_EXEC:
      if (SYSDEBUG) printf("exec!\n");
      if (!is_valid_string((char *)*(cur_esp + 1), f->esp) || !is_user_vaddr(cur_esp + 1)) 
      	sys_exit(-1, f);
      	
      f->eax = process_execute((char*)*(cur_esp + 1));
      setpin_string((void *)*(cur_esp + 1), false);
      break;
      
    case SYS_WAIT:
      if (SYSDEBUG) printf("wait!\n");
      if (!is_user_vaddr(cur_esp + 1))
        sys_exit(-1, f);
      f->eax = process_wait((pid_t)*(cur_esp + 1));
      break;
      
    case SYS_CREATE:
      if (SYSDEBUG) printf("create!\n");
      if (!is_valid_string((char *)*(cur_esp + 1), f->esp) || !is_user_vaddr(cur_esp + 2) || strlen((char *)*(cur_esp + 1)) == 0) 
      	sys_exit(-1, f);
      lock_acquire(&file_lock);
      if (strlen((char *)*(cur_esp + 1)) > 14) f->eax = 0;
      else f->eax = filesys_create((char *)*(cur_esp + 1), (unsigned)*(cur_esp + 2));
      lock_release(&file_lock);
      setpin_string((void *)*(cur_esp + 1), false);
      break;
      
    case SYS_REMOVE:
      if (SYSDEBUG) printf("remove!\n");
      if (!is_valid_string((char *)*(cur_esp + 1), f->esp) || !is_user_vaddr(cur_esp + 1) || strlen((char *)*(cur_esp + 1)) == 0) 
      	sys_exit(-1, f);

      lock_acquire(&file_lock);
      f->eax = filesys_remove((char *)*(cur_esp + 1));	
      lock_release(&file_lock);
      setpin_string((void *)*(cur_esp + 1), false);
      break;
      
    case SYS_OPEN:
      if (SYSDEBUG) printf("open!\n");
      if (!is_valid_string((char *)*(cur_esp + 1), f->esp) || !is_user_vaddr(cur_esp + 1)) 
      	sys_exit(-1, f);

      lock_acquire(&file_lock);
      if ((fp = filesys_open((char *)*(cur_esp + 1))) != NULL){
        /* If filename is current thread, deny writing! */
        if (!strcmp(thread_current()->name, (char *)*(cur_esp + 1))){
          file_deny_write(fp);
        }
        f->eax = fd_add(fp);
      }
      else
        f->eax = -1;
      lock_release(&file_lock);
      setpin_string((void *)*(cur_esp + 1), false);
      break;
      
    case SYS_FILESIZE:
      if (SYSDEBUG) printf("filesize!\n");
      if (!is_user_vaddr(cur_esp + 1) || (fd = (int)*(cur_esp + 1)) < 3)
        sys_exit(-1, f);
      
      f->eax = inode_length(file_get_inode(fd_get_file(fd)));
      break;
      
    case SYS_READ:
      if (SYSDEBUG) printf("read!\n");
      if (!is_user_vaddr(cur_esp + 1) || !is_user_vaddr(cur_esp + 3))
        sys_exit(-1, f);
      
      len = (unsigned)*(cur_esp + 3);
      if (!is_valid_buffer ((char *)*(cur_esp + 2), f->esp, len, true)) 
      	sys_exit(-1, f);

      if (len <= 0) { f->eax = 0; break;}
      buf = (char *)*(cur_esp + 2);
      
      lock_acquire(&file_lock);
      if ((fd = (int)*(cur_esp + 1)) == 0)
      {
        for (i = 0; i < len && (inp = input_getc()) != 0; i++)
        {
          *(buf++) = inp; /* Modified */

        }
        *buf = 0;

        f->eax = i;
      }
      else if (fd < 3)
      {
        lock_release(&file_lock);
        sys_exit(-1, f);
      }
      else
      {
        if ((fp = fd_get_file(fd)) != NULL) {
          #ifdef DEBUGTOOL
          printf("start reading for file at 0x%x, to 0x%x, length %d\n", fp, buf, len);
          #endif.
          f->eax = file_read(fp, buf, len);
          #ifdef DEBUGTOOL
          printf("end reading\n");
          #endif
        }
        else f->eax = -1;
      }
      lock_release(&file_lock);
      setpin_buffer((void *)*(cur_esp + 2), (size_t) len, false);
      break;
      
    case SYS_WRITE:
      if (SYSDEBUG) printf("write!\n");
      if (!is_user_vaddr(cur_esp + 1) || !is_user_vaddr(cur_esp + 3))
        sys_exit(-1, f);
      
      len = (unsigned)*(cur_esp + 3);
      if (!is_valid_buffer ((char *)*(cur_esp + 2), f->esp, len, false)) 
      	sys_exit(-1, f);
      	
      len = (unsigned)*(cur_esp + 3);
      if (len <= 0){f->eax = 0; break;}
      buf = (char *)*(cur_esp + 2);
      
      lock_acquire(&file_lock);
      if((fd = (int)*(cur_esp + 1)) == 1)
      {
        for (i = 0; *(buf) != 0; i++)
        {
          printf("%c", *(buf++));
        }
        f->eax = i;
      }
      else if (fd < 3)
      {
        lock_release(&file_lock);
        sys_exit(-1, f);
      }
      else
      {
        /* if fp is the file pointer of current file, do not write */
        fp = fd_get_file(fd);
        if (!fp || file_is_directory(fp)){
          f->eax = -1;
        }
        else {
          if (fp->deny_write) f->eax = 0;
          else {
            f->eax = file_write(fd_get_file(fd), buf, len);
          }
        }
      }
      lock_release(&file_lock);
      setpin_buffer((void *)*(cur_esp + 2), len, false);
      break;
      
    case SYS_SEEK:
      if (SYSDEBUG) printf("seek!\n");
      if (!is_user_vaddr(cur_esp + 2) || (fd = (int)*(cur_esp + 1)) < 3)
        sys_exit(-1, f);
        
      file_seek(fd_get_file(fd), (unsigned)*(cur_esp + 2));
      break;      
      
    case SYS_TELL:
      if (SYSDEBUG) printf("tell!\n");
      if (!is_user_vaddr(cur_esp + 1) || (fd = (int)*(cur_esp + 1)) < 3)
        sys_exit(-1, f);
        
      f->eax = file_tell(fd_get_file(fd));
      break;
      
    case SYS_CLOSE:
      if (SYSDEBUG) printf("close!\n");
      sys_close ((int)*(cur_esp + 1), f);
      break;
      
    case SYS_MMAP:
      if (SYSDEBUG) printf("mmap!\n");
      if (!is_user_vaddr(cur_esp + 1) || !is_user_vaddr(cur_esp + 2)){
        sys_exit(-1, f);
      }
      if (*(cur_esp + 1) < 2 || !is_user_vaddr(*(cur_esp + 2)) || (*(cur_esp + 2)) % PGSIZE != 0 || (*(cur_esp + 2)) == 0 || *(cur_esp + 2) < 0x10000000 || *(cur_esp + 2) >= PHYS_BASE - STACK_GROW_MAX){
        f->eax = -1;
        break;
      }
      struct file *f_innocent = fd_get_file(*(cur_esp + 1));
      if (!f_innocent || file_length(f_innocent) == 0){
        f->eax = -1;
        break;
      }
      struct file *f_for_mmap = file_reopen(f_innocent);
      int mid = get_mid();
      int32_t ofs = 0;
      uint32_t read_bytes = file_length(f_for_mmap);
      uint8_t *upage = *(cur_esp + 2);
      
      f->eax = mid;
      while(read_bytes > 0){
        uint32_t page_read_bytes = read_bytes > PGSIZE ? PGSIZE : read_bytes;
        uint32_t page_zero_bytes = PGSIZE - page_read_bytes;
        /* disallow memory overlapping */
        if (get_spte(upage) != NULL){
          delete_mmap_at_mid(mid);
          f->eax = -1;
          break;
        }
        if (!locate_mmap_to_table(mid, f_for_mmap, ofs, upage, page_read_bytes, page_zero_bytes)){
          delete_mmap_at_mid(mid);
          f->eax = -1;
          break;
        }
        read_bytes -= page_read_bytes;
        ofs += page_read_bytes;
        upage += PGSIZE;
      }
      break;
    
    case SYS_MUNMAP:
      if (SYSDEBUG) printf("munmap\n");
      if (!is_user_vaddr(cur_esp + 1)){
        sys_exit(-1, f);
      }
      delete_mmap_at_mid(*(cur_esp + 1));
      break;
      
    case SYS_ISDIR:
      if (!is_user_vaddr(cur_esp + 1)) sys_exit(-1, f);
      fd = *(cur_esp + 1);
      fp = fd_get_file(fd);
      if (fp == NULL)
        PANIC ("Not valid fd!\n");
      f->eax = is_directory_inode (fp->inode);
      break;
      
    case SYS_CHDIR:
      if (!is_valid_string((char *)*(cur_esp + 1), f->esp)) sys_exit(-1, f);
      f->eax = filesys_chdir((char *)*(cur_esp + 1));
      break;
    
    case SYS_MKDIR:
      if (!is_valid_string((char *)*(cur_esp + 1), f->esp)) sys_exit(-1, f);
      f->eax = filesys_mkdir((char *)*(cur_esp + 1));
      break;
    
    case SYS_READDIR:
      if(!is_user_vaddr(cur_esp + 1) || !is_valid_string((char *)*(cur_esp + 2), f->esp)) sys_exit(-1, f);
      fd = *(cur_esp + 1);
      fp = fd_get_file(fd);

      if (!fp) sys_exit(-1, f);

      struct inode *inode = file_get_inode(fp);

      if(!inode || !is_directory_inode(inode)){
        f->eax = false;
        break;
      }
      struct dir *dir_to_read = dir_open(inode);
      if (!dir_to_read){
        f->eax = false;
        break;
      }
      
      off_t *readpoint = (off_t *) fp + 1;
      bool result = true;
      for(i = 0; i <= *readpoint; i++){
        result = dir_readdir(dir_to_read, (char *)*(cur_esp + 2));
        if (!result) break;
      }
      if (i > *readpoint) (*readpoint)++;
      
      f->eax = result;
      
      break;
    
    case SYS_INUMBER:
      if(!is_user_vaddr(cur_esp + 1)) sys_exit(-1, f);
      fp = fd_get_file(*(cur_esp + 1));
      if(!fp) sys_exit(-1, f);
      f->eax = inode_get_inumber(file_get_inode(fp));
      break;
      
    default:
      thread_exit();
  }
  setpin_ptr(cur_esp, false);
  //printf("Survive Signal %d at %x!\n", *cur_esp, cur_esp);
}

/* Added: check validity of arguments and terminate the thread
   if there are invalid arguments. We should release locks and free
   allocations. */
bool
is_valid_ptr (void * ptr, void * esp)
{
  if (ptr != NULL && is_user_vaddr(ptr) && ptr > 0x08048000){
    struct sup_page_elem *spte = get_spte(ptr);
    if(spte != NULL){
      lazy_load(spte);
      setpin_ptr(ptr, spte->is_loaded);
      return spte->is_loaded;
    }
    else if(pagedir_get_page(thread_current()->pagedir, ptr) != NULL)
      return true;
    else if (ptr >= esp - 32){
      #ifdef DEBUGTOOL
      printf("expand stack for 0x%x for esp 0x%x\n", ptr, esp);
      #endif
      return expand_stack(ptr);
    }
  }
  return false;
}

bool
is_valid_string (void * ptr, void * esp)
{
  char * p = (char *)ptr;
  if (!is_valid_ptr((void *) p, esp)) return false;
  while(*p != 0){
    if (!is_valid_ptr((void *) p, esp)) return false;
    p++;
  }
  return true;
}

bool 
is_valid_buffer (void * ptr, void * esp, size_t size, bool be_write) 
{
  size_t i;
  void *p = ptr;
  struct sup_page_elem *spte;
  
  for (i = 0; i < size; i++) {
    if (!is_valid_ptr(p, esp)) return false;
    spte = get_spte(p);
    if (spte && be_write && !spte->writable) return false;
    p++;
  }
  return true;
}

void
setpin_ptr(void * ptr, bool pin) {
  get_spte(ptr)->pinned = pin;
}

void setpin_string (void * ptr, bool pin){
  char * p = (char *) ptr;
  setpin_ptr(p, pin);
  while (*p != 0){
    setpin_ptr(p, pin);
    p++;
  }
}

void setpin_buffer (void * ptr, size_t size, bool pin){
  unsigned i;
  char *p = (char *) ptr;
  for (i = 0; i < size; i++){
    setpin_ptr(p, pin);
    p++;
  }
}

void 
sys_close (int fd, struct intr_frame *f)
{
  struct file *fp;
  
  if (!is_user_vaddr(f->esp + 4) || fd < 3)
    sys_exit(-1, f);

  lock_acquire(&file_lock);
  if ((fp = fd_get_file(fd)) != NULL) {
    file_close(fp); 
    fd_delete(fd);
  }
  lock_release(&file_lock);
}

void
sys_exit (int status, struct intr_frame *f) 
{
  int i;
  struct list_elem *e;

  printf("%s: exit(%d)\n", thread_current()->name, status);
  
  if (is_user_vaddr(f->esp + 4)) {
    for (i = 0; i < MAX_FD; i++) {
      sys_close(i + 3, f);
    }
  }
  
  thread_current()->exit_status = status;
  f->eax = status;
  thread_exit();
}









