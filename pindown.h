#ifndef _SECURITY_DEMO_H
#define _SECURITY_DEMO_H
#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
//#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/ext2_fs.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/kd.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/quota.h>
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>

#include <linux/audit.h>
#include <linux/string.h>
#include <linux/binfmts.h>

#define MAX_PATHLEN 128  //the max length of path

typedef struct pindown_security_t {
  char bprm_pathname[MAX_PATHLEN];
  u32 pathlen;
} pindown_security_t;


MODULE_LICENSE("GPL");

#define INITCONTEXTLEN 100
#define XATTR_SAMPLE_SUFFIX "pindown"
#define XATTR_NAME_SAMPLE XATTR_SECURITY_PREFIX XATTR_SAMPLE_SUFFIX

#endif