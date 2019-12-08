#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  cache_init(); // Added: initialize cache
  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();

  /* Added: set cur_dir of current thread to root directory. */
  thread_current()->cur_dir = dir_open_root();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  cache_term ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  block_sector_t inode_sector = 0;
  /* Added: file_name stores file name to run. */
  char file_name[NAME_MAX + 1];
  
  struct dir *dir = dir_parse_and_open(name, file_name);

  bool success = (dir != NULL) && free_map_allocate (1, &inode_sector)
                               && inode_create (inode_sector, initial_size, 0)
                               && dir_add (dir, file_name, inode_sector);
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  
  dir_close (dir);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  /* Modified: to apply Subdirectories */
  char *file_name[NAME_MAX + 1];
  
  struct dir *dir = dir_parse_and_open (name, file_name);
  struct inode *inode = NULL;

  if (dir != NULL){
    inode = dir_get_inode(dir);
    if (strlen(file_name) > 0) dir_lookup (dir, file_name, &inode);
  }
  dir_close (dir);
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  bool success = false;

  /* Modified: to apply Subdirectories */
  char *file_name[NAME_MAX + 1];
  
  struct dir *dir = dir_parse_and_open (name, file_name);
  struct dir *dir_to_remove;
  char nouse[256];

  if (!dir) return false;
  
  //char temp[NAME_MAX + 1];
  //printf("ㅏ current dir ㅓ\n");
  //while (dir_readdir(dir, temp))
  //  printf("  %s\n", temp);
  //printf("ㅏ    temp     ㅓ\n");

  /* If file_name is "." or "..", reject deletion */
  if (!strcmp(file_name, ".") || !strcmp(file_name, "..")) return false;
  
  struct inode *inode;
  dir_lookup(dir, file_name, &inode);
  
  if (!inode) {
    success = false;
  }
  else if (!is_directory_inode(inode)){
    success = dir_remove(dir, file_name);
  }
  else if((dir_to_remove = dir_open(inode)) && !dir_readdir(dir_to_remove, nouse)){
    success = dir_remove(dir_to_remove, ".")
           && dir_remove(dir, file_name);
    dir_close(dir_to_remove);
  }
  dir_close (dir); 
  
  /* the case that dir_to_remove is not closed */
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
    
  /* Added: add "." and ".." directory to root */
  struct dir *root = dir_open_root();
  dir_add(root, ".", ROOT_DIR_SECTOR);
  dir_add(root, "..", ROOT_DIR_SECTOR);
  dir_close(root);
  
  free_map_close ();
  printf ("done.\n");
}

/* Added: parse and go to the target directory and store file name to second parameter. */
struct dir *dir_parse_and_open(char *path, char *file_name){
  if (!path) return NULL;
  if (!file_name) return NULL;
  if (strlen(path) == 0) return NULL;

  struct inode *tempinode;
  struct dir *tempdir;
  if (path[0] == '/'){
    tempdir = dir_open_root();
  }
  else{
    tempdir = dir_reopen(thread_current()->cur_dir);
  }
  
  if (!tempdir) return NULL;
  if (!dir_lookup((const struct dir *)tempdir, ".", &tempinode)) return NULL;

  char *token, *oldtoken, *save_ptr = NULL;
  char cp_path[256];
  strlcpy(cp_path, path, 255);
  oldtoken = strtok_r(cp_path, "/", &save_ptr);
  token = strtok_r(NULL, "/", &save_ptr);

  while (oldtoken != NULL && token != NULL){
    tempinode = NULL;

    if (!dir_lookup((const struct dir *)tempdir, (const char *)oldtoken, &tempinode)){
      dir_close(tempdir);
      return NULL;
    }
    else if (!is_directory_inode(tempinode)){
      dir_close(tempdir);
      return NULL;
    }
    else {
      dir_close(tempdir);
      tempdir = dir_open(tempinode);
    }
    oldtoken = token;
    token = strtok_r(NULL, "/", &save_ptr);
  }
  if (oldtoken) strlcpy(file_name, oldtoken, NAME_MAX + 1);
  else if (token) strlcpy(file_name, token, NAME_MAX + 1);
  else strlcpy(file_name, "", NAME_MAX + 1);
  return tempdir;
}

/* Added: system call handler */
bool filesys_mkdir(char *path){
  bool success = false;
  char dir_name[NAME_MAX + 1];

  struct dir *dir = dir_parse_and_open(path, dir_name);
  block_sector_t sector = 0;

  success = dir != NULL && free_map_allocate (1, &sector)
                  && dir_create (sector, 16)
                  && dir_add (dir, dir_name, sector);

  if (!success && sector != 0) 
    free_map_release (sector, 1);

  /* if success, add '.' and '..' to created directory */
  if (success){
    struct dir *created = dir_open(inode_open(sector));
    if (created){
      dir_add(created, ".", sector);
      dir_add(created, "..", inode_get_inumber(dir_get_inode(dir)));
      dir_close(created);
    }
  }
  dir_close (dir);
  return success;
}

/* Added: system call handler */
bool filesys_chdir(char * path){
  char dir_name[NAME_MAX + 1];
  struct dir *dir = dir_parse_and_open(path, dir_name);
  struct inode *inode;
  
  /* Because dir_parse_and_open follows except the last path(dir_name here),
     I have to go one step more. */
  if (!dir_lookup((const struct dir *)dir, (const char *)dir_name, &inode)){
    dir_close(dir);
    return false;
  }
  else if(!is_directory_inode(inode)){
    dir_close(dir);
    return false;
  }
  else{
    dir_close(dir);
    dir = dir_open(inode);
  }
  
  /* If directory followed by path is valid, change current thread's directory. */
  if (dir) {
    dir_close(thread_current()->cur_dir);
    thread_current()->cur_dir = dir;
    return true;
  }
  else{
    return false;
  }
}
