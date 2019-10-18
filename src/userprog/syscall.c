#include "userprog/syscall.h"
#include <stdio.h>
#include "lib/user/syscall.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/fd.h"
#include "threads/synch.h"

struct lock *file_lock;

static void syscall_handler (struct intr_frame *);
/* Added: check each arguments are valid, and terminate the process if
   the arguments are invalid. */
bool is_valid_ptr (void * ptr);

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
  if (!is_valid_ptr((uint32_t *)f->esp))
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
      if (!is_valid_ptr((char *)*(cur_esp + 1)) || !is_user_vaddr(cur_esp + 1)) 
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
      if (!is_valid_ptr((char *)*(cur_esp + 1)) || !is_user_vaddr(cur_esp + 2) || strlen((char *)*(cur_esp + 1)) == 0) 
      	sys_exit(-1, f);
      	
      lock_acquire(&file_lock);
      if (strlen((char *)*(cur_esp + 1)) > 14) f->eax = 0;
      else f->eax = filesys_create((char *)*(cur_esp + 1), (unsigned)*(cur_esp + 2));
      lock_release(&file_lock);
      break;
      
    case SYS_REMOVE:
      //printf("remove!\n");
      if (!is_valid_ptr((char *)*(cur_esp + 1)) || !is_user_vaddr(cur_esp + 1) || strlen((char *)*(cur_esp + 1)) == 0) 
      	sys_exit(-1, f);
     
      lock_acquire(&file_lock);
      f->eax = filesys_remove((char *)*(cur_esp + 1));	
      lock_release(&file_lock);
      break;
      
    case SYS_OPEN:
      //printf("open!\n");
      if (!is_valid_ptr((char *)*(cur_esp + 1)) || !is_user_vaddr(cur_esp + 1)) 
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
      if (!is_valid_ptr((char *)*(cur_esp + 2)) || !is_user_vaddr(cur_esp + 3)) 
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
          f->eax = file_read(fd_get_file(fd), buf, len);
        }
        else f->eax = -1;
      }
      lock_release(&file_lock);
      break;
      
    case SYS_WRITE:
      //printf("write!\n");
      if (!is_valid_ptr((char *)*(cur_esp + 2)) || !is_user_vaddr(cur_esp + 3)) 
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
          else
            f->eax = file_write(fd_get_file(fd), buf, len);
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
      if (!is_user_vaddr(cur_esp + 1) || (fd = (int)*(cur_esp + 1)) < 3)
        sys_exit(-1, f);
        
      lock_acquire(&file_lock);
      if ((fp = fd_get_file(fd)) != NULL) {
        file_close(fp); 
        fd_delete(fd);
      }
      lock_release(&file_lock);
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
is_valid_ptr (void * ptr)
{
  if (ptr != NULL && is_user_vaddr(ptr))
    if(pagedir_get_page(thread_current()->pagedir, ptr) != NULL)
      return true;
  //printf("Your arguments are invalid: %x\n", ptr);
  return false;
}

void
sys_exit (int status, struct intr_frame *f) 
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_current()->exit_status = status;
  f->eax = status;
  thread_exit();
}









