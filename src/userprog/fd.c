/* Added : file for file descriptor used in syscall.c */

#include <stdio.h>
#include <stdlib.h>
#include "threads/thread.h"
#include "userprog/fd.h"
#include "filesys/file.h"

int
fd_add (struct file *f)
{
  int i;
  for (i = 0; CURRENT_FD(i) != NULL && i < MAX_FD; i++) {;}
  ASSERT(i < MAX_FD);
  
  CURRENT_FD(i) = f;
  return i + 3; // except 0(stdin), 1(stdout), 2(stderr)
}

void
fd_delete (int fd)
{
  ASSERT(fd > 3); // assert if fd is not valid
  
  CURRENT_FD(fd - 3) = NULL;
}

struct file *
fd_get_file (int fd)
{
  ASSERT(fd > 3); // assert if fd is not valid
  
  return CURRENT_FD(fd - 3);
}
