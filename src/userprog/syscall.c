#include "userprog/syscall.h"
#include <stdio.h>
#include "lib/user/syscall.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t *cur_esp = (uint32_t *)f->esp;
  uint32_t *cur_eax = (uint32_t *)f->eax;
  
  struct file *fd;
  int i, len;
  char *buf;
  char inp;
  
  hex_dump(cur_esp, cur_esp, 100, 1);
  
  printf("0x%x, cur_esp = %d\n", cur_esp, *cur_esp);
  
  switch(*cur_esp) {
    case SYS_HALT :			/* Halt the operating system. */
      shutdown_power_off();
      NOT_REACHED();
      break;
      
    case SYS_EXIT :			/* Terminate this process. */
      //args1 : (int)*(cur_esp + 4)
      *cur_eax = (int)*(cur_esp + 4);
      thread_exit();
      break;
      
    case SYS_EXEC :			/* Start another process. */
      //args1 : (char *)*(cur_esp + 4)
      *cur_eax = process_execute((char *)*(cur_esp + 4));
      break; // need to be synchronized
      
    case SYS_WAIT :			/* Wait for a child process to die. */
      //args1 : (pid_t)*(cur_esp + 4)
      printf("args1 = %d\n", (pid_t)*(cur_esp + 4));
      break; // najungs
      
    case SYS_CREATE :			/* Create a file. */
      //args1 : (char *)*(cur_esp + 4)
      //args2 : (unsigned)*(cur_esp + 8)
      *cur_eax = filesys_create((char *)*(cur_esp + 4), (unsigned)*(cur_esp + 8));
      break;
      
    case SYS_REMOVE :			/* Delete a file. */
      //args1 : (char *)*(cur_esp + 4)
      *cur_eax = filesys_remove((char *)*(cur_esp + 4));
      break;
      
    case SYS_OPEN :			/* Open a file. */
      //args1 : (char *)*(cur_esp + 4)
      *cur_eax = (int)filesys_open((char *)*(cur_esp + 4));
      break;
      
    case SYS_FILESIZE :			/* Obtain a file's size. */
      //args1 : (int)*(cur_esp + 4)
      *cur_eax = inode_length(file_get_inode((struct file *)*(cur_esp + 4)));
      break;
      
    case SYS_READ :			/* Read from a file. */
      //args1 : (int)*(cur_esp + 4)
      //args2 : (void *)*(cur_esp + 8)
      //args3 : (unsigned)*(cur_esp + 12)
      len = (unsigned)*(cur_esp + 12);
      if (len-- <= 0) { *cur_eax = 0; break; }
      buf = (char *)*(cur_esp + 8);
      
      if ((fd = (struct file *)*(cur_esp + 4)) == 0) {
        for (i = 0; i < len && (inp = input_getc()) != 0; i++) {
          *(buf++) = input_getc();
        }
        *buf = 0;
        *cur_eax = i;
      }
      else {
        *cur_eax = file_read(fd, buf, len);
      }
      
      break;	
      
    case SYS_WRITE :			/* Write to a file. */
      //args1 : (int)*(cur_esp + 4)
      //args2 : (void *)*(cur_esp + 8)
      //args3 : (unsigned)*(cur_esp + 12)
      len = (unsigned)*(cur_esp + 12);
      if (len-- <= 0) { *cur_eax = 0; break; }
      buf = (char *)*(cur_esp + 8);
      
      if ((fd = (struct file *)*(cur_esp + 4)) == 1) {
        for (i = 0; i < len && i < strlen(buf) != 0; i++) {
          printf("%c", *(buf++));
        }
        *cur_eax = i;
      }
      else {
        *cur_eax = file_write(fd, buf, len);
      }
      break;
      
    case SYS_SEEK :			/* Change position in a file. */
      //args1 : (int)*(cur_esp + 4)
      //args2 : (unsigned)*(cur_esp + 8)
      file_seek((struct file *)*(cur_esp + 4), (unsigned)*(cur_esp + 8));
      break;
      
    case SYS_TELL :			/* Report current position in a file. */
      //args1 : (int)*(cur_esp + 4)
      *cur_eax = file_tell((struct file *)*(cur_esp + 4));
      break;
      
    case SYS_CLOSE :			/* Close a file. */
      //args1 : (int)*(cur_esp + 4)
      *cur_eax = file_close ((struct file *)*(cur_esp + 4));
      break;
  }
  
  thread_exit ();
}
