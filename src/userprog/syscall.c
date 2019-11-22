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

static void syscall_handler (struct intr_frame *);
/* Added: check each arguments are valid, and terminate the process if
   the arguments are invalid. */
bool is_valid_ptr (void * ptr, void *esp);

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
  if (!is_valid_ptr((uint32_t *)f->esp, f->esp))
    sys_exit(-1, f);
    
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
      //printf("halt!\n");
      shutdown_power_off();
      NOT_REACHED();
      break; 
      
    case SYS_EXIT:
      if (!is_user_vaddr(cur_esp + 1))
        sys_exit(-1, f);
        
      sys_exit((int)*(cur_esp + 1), f);
      break;
      
    case SYS_EXEC:
      //printf("exec!\n");
      if (!is_valid_ptr((char *)*(cur_esp + 1), f->esp) || !is_user_vaddr(cur_esp + 1)) 
      	sys_exit(-1, f);
      	
      f->eax = process_execute((char*)*(cur_esp + 1));
      break;
      
    case SYS_WAIT:
      //printf("wait!\n");
      if (!is_user_vaddr(cur_esp + 1))
        sys_exit(-1, f);
      f->eax = process_wait((pid_t)*(cur_esp + 1));
      break;
      
    case SYS_CREATE:
      //printf("create!\n");
      if (!is_valid_ptr((char *)*(cur_esp + 1), f->esp) || !is_user_vaddr(cur_esp + 2) || strlen((char *)*(cur_esp + 1)) == 0) 
      	sys_exit(-1, f);
      	
      lock_acquire(&file_lock);
      if (strlen((char *)*(cur_esp + 1)) > 14) f->eax = 0;
      else f->eax = filesys_create((char *)*(cur_esp + 1), (unsigned)*(cur_esp + 2));
      lock_release(&file_lock);
      break;
      
    case SYS_REMOVE:
      //printf("remove!\n");
      if (!is_valid_ptr((char *)*(cur_esp + 1), f->esp) || !is_user_vaddr(cur_esp + 1) || strlen((char *)*(cur_esp + 1)) == 0) 
      	sys_exit(-1, f);
     
      lock_acquire(&file_lock);
      f->eax = filesys_remove((char *)*(cur_esp + 1));	
      lock_release(&file_lock);
      break;
      
    case SYS_OPEN:
      //printf("open!\n");
      if (!is_valid_ptr((char *)*(cur_esp + 1), f->esp) || !is_user_vaddr(cur_esp + 1)) 
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
      break;
      
    case SYS_FILESIZE:
      //printf("filesize!\n");
      if (!is_user_vaddr(cur_esp + 1) || (fd = (int)*(cur_esp + 1)) < 3)
        sys_exit(-1, f);
      
      f->eax = inode_length(file_get_inode(fd_get_file(fd)));
      break;
      
    case SYS_READ:
      //printf("read!\n");
      if (!is_valid_ptr((char *)*(cur_esp + 2), f->esp) || !is_user_vaddr(cur_esp + 3)) 
      	sys_exit(-1, f);
        
      len = (unsigned)*(cur_esp + 3);

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
          #endif
          f->eax = file_read(fp, buf, len);
          #ifdef DEBUGTOOL
          printf("end reading\n");
          #endif
        }
        else f->eax = -1;
      }
      lock_release(&file_lock);
      break;
      
    case SYS_WRITE:
      //printf("write!\n");
      if (!is_valid_ptr((char *)*(cur_esp + 2), f->esp) || !is_user_vaddr(cur_esp + 3)) 
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
        if (fp != NULL) {
          if (fp->deny_write)
            f->eax = 0;
          else{
            #ifdef DEBUGTOOL
            printf("start writing for file at 0x%x, to 0x%x, length %d\n", fp, buf, len);
            #endif
            f->eax = file_write(fd_get_file(fd), buf, len);
          }
        }
        else f->eax = -1;
      }
      lock_release(&file_lock);
      break;
      
    case SYS_SEEK:
      //printf("seek!\n");
      if (!is_user_vaddr(cur_esp + 2) || (fd = (int)*(cur_esp + 1)) < 3)
        sys_exit(-1, f);
        
      file_seek(fd_get_file(fd), (unsigned)*(cur_esp + 2));
      break;      
      
    case SYS_TELL:
      //printf("tell!\n");
      if (!is_user_vaddr(cur_esp + 1) || (fd = (int)*(cur_esp + 1)) < 3)
        sys_exit(-1, f);
        
      f->eax = file_tell(fd_get_file(fd));
      break;
      
    case SYS_CLOSE:
      //printf("close!\n");
      sys_close ((int)*(cur_esp + 1), f);
      break;
      
    case SYS_MMAP:
      //printf("mmap!\n");
      if (!is_user_vaddr(cur_esp + 1) || !is_user_vaddr(cur_esp + 2)){
        sys_exit(-1, f);
      }
      if (*(cur_esp + 1) < 2 || !is_user_vaddr(*(cur_esp + 2)) || (*(cur_esp + 2)) % PGSIZE != 0 || (*(cur_esp + 2)) == 0){
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
      void *upage = *(cur_esp + 2);
      
      while(read_bytes > 0){
        uint32_t page_read_bytes = read_bytes > PGSIZE ? PGSIZE : read_bytes;
        uint32_t page_zero_bytes = PGSIZE - page_read_bytes;
        if (!add_mmap_to_page_table(f_for_mmap, ofs, upage, page_read_bytes, page_zero_bytes)){
          delete_mmap_at_mid(mid);
          f->eax = -1;
        }
        read_bytes -= page_read_bytes;
        ofs += page_read_bytes;
        upage += PGSIZE;
      }
      f->eax = mid;
      break;
    
    case SYS_MUNMAP:
      //printf("munmap\n");
      if (!is_user_vaddr(cur_esp + 1)){
        sys_exit(-1, f);
      }
      delete_mmap_at_mid(*(cur_esp + 1));
      break;
        
    default:
      thread_exit();
  }
  //printf("Survive Signal %d at %x!\n", *cur_esp, cur_esp);
}

/* Added: check validity of arguments and terminate the thread
   if there are invalid arguments. We should release locks and free
   allocations. */
bool
is_valid_ptr (void * ptr, void * esp)
{
  if (ptr != NULL && is_user_vaddr(ptr)){
    struct sup_page_elem *spte = get_spte(ptr);
    if(pagedir_get_page(thread_current()->pagedir, ptr) != NULL)
      return true;
    else if(spte != NULL){
      load_page(spte);
      return spte->is_loaded;
    }
    else if (ptr >= esp - 32){
      #ifdef DEBUGTOOL
      printf("expand stack for 0x%x for esp 0x%x\n", ptr, esp);
      #endif
      return expand_stack(ptr);
    }
  }
  return false;
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









