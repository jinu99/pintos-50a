#include "userprog/syscall.h"
#include <stdio.h>
#include "lib/user/syscall.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/user/syscall.h"

static void syscall_handler (struct intr_frame *);
/* Added: check each arguments are valid, and terminate the process if
   the arguments are invalid. */
void valid_ptr_or_die (void * ptr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* Added: handle each syscalls */
  uint32_t *cur_esp = (uint32_t *)f->esp;
  uint32_t cur_eax = (uint32_t)f->eax; /* For return value of intr_frame */
  
  struct file *fd;
  int i, len;
  char *buf;
  char inp;
  
  //hex_dump(cur_esp, cur_esp, 100, true);
  switch (*cur_esp)
  {
    case SYS_HALT:
      printf("halt!\n");
      shutdown_power_off();
      NOT_REACHED();
      break; 
    case SYS_EXIT:
      printf("%s: exit(%d)\n", thread_current()->name, (int)*(cur_esp + 1));
      cur_eax = (int)*(cur_esp + 1);
      thread_exit();
      break;
    case SYS_EXEC:
      printf("exec!\n");
      valid_ptr_or_die ((char *)*(cur_esp + 4));
      cur_eax = process_execute((char*)*(cur_esp + 4));
      break;
    case SYS_WAIT:
      printf("wait!\n");
      cur_eax = process_wait((pid_t)*(cur_esp + 4));
      break;
    case SYS_CREATE:
      printf("create!\n");
      valid_ptr_or_die ((char *)*(cur_esp + 4));
      cur_eax = filesys_create((char *)*(cur_esp + 4), (unsigned)*(cur_esp + 8));
      break;
    case SYS_REMOVE:
      printf("remove!\n");
      valid_ptr_or_die ((char *)*(cur_esp + 4));
      cur_eax = filesys_remove((char *)*(cur_esp+4));
      break;
    case SYS_OPEN:
      printf("open!\n");
      valid_ptr_or_die ((char *)*(cur_esp + 4));
      cur_eax = (int)filesys_open((char *)*(cur_esp + 4));
      break;
    case SYS_FILESIZE:
      printf("filesize!\n");
      cur_eax = inode_length(file_get_inode((struct file *)*(cur_esp + 4)));
      break;
    case SYS_READ:
      printf("read!\n");
      valid_ptr_or_die ((char *)*(cur_esp + 8));
      len = (unsigned)*(cur_esp + 12);
      if (len-- <= 0) { cur_eax = 0; break;}
      buf = (char *)*(cur_esp + 8);
      if ((fd = (struct file *)*(cur_esp + 4)) == 0)
      {
        for (i = 0; i < len && (inp = input_getc()) != 0; i++)
        {
          *(buf++) = inp; /* Modified */

        }
        *buf = 0;
        cur_eax = i;
      }
      else
      {
        cur_eax = file_read(fd, buf, len);
      }
      break;
    case SYS_WRITE:
      printf("write!\n");
      valid_ptr_or_die ((char *)*(cur_esp + 2));
      len = (unsigned)*(cur_esp + 3);
      if (len-- <= 0){cur_eax = 0; break;}
      buf = (char *)*(cur_esp + 2);
      
      if((fd = (struct file *)*(cur_esp + 1)) == 1)
      {
        for (i = 0; i < len && *(buf) != NULL; i++)
        {
          printf("%c", *(buf++));
        }
        cur_eax = i;
      }
      else
      {
        cur_eax = file_write(fd, buf, len);
      }
      break;
    case SYS_SEEK:
      printf("seek!\n");
      file_seek((struct file *)*(cur_esp + 4), (unsigned)*(cur_esp + 8));
      break;      
    case SYS_TELL:
      printf("tell!\n");
      cur_eax = file_tell((struct file *)*(cur_esp + 4));
      break;
    case SYS_CLOSE:
      printf("close!\n");
      cur_eax = file_close((struct file *)*(cur_esp + 4));
      break;
    default:
      thread_exit();
  }
  //printf("Survive Signal %d at %x!\n", *cur_esp, cur_esp);
}

/* Added: check validity of arguments and terminate the thread
   if there are invalid arguments. We should release locks and free
   allocations. */
void
valid_ptr_or_die (void * ptr)
{
  if (ptr != NULL)
    if(pagedir_get_page(thread_current()->pagedir, ptr) != NULL)
      return;
  printf("Your arguments are invalid: %x\n", ptr);
  thread_exit();
}
