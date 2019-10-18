/* Added : header file for file descriptor used in syscall.c */

#ifndef USERPROG_FD_H
#define USERPROG_FD_H

#include <stdio.h>
#include "threads/thread.h"
#include "filesys/file.h"

#define CURRENT_FD(int)		(thread_current()->fd)[int]

#define MAX_FD 128

int fd_add (struct file *f);
void fd_delete (int fd);
struct file * fd_get_file (int fd);

#endif
