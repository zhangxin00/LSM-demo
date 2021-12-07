#include "demo.h"

//对hook函数进行填充，添加自己的逻辑（安全检查）,这里让它输出一条内核信息。
static unsigned long long count1 = 0;
static unsigned long long count2 = 0;

//get the xattr value from inode
char *get_inode_policy2(struct inode *inode, const char *name)
{
	char *pathname =
		(char *)kzalloc(sizeof(char) * MAX_PATHLEN, GFP_KERNEL);
	if (!pathname) {
		return pathname;
	}
	pathname[0] = 's';
	pathname[1] = '\0';
	return pathname;
}
char *get_inode_policy(struct inode *inode, const char *name)
{
	struct dentry *dentry;
	char *pathname = NULL;
	int rc;
	int len;
	if (!inode || !inode->i_op) {
		return pathname;
	}
	dentry = d_find_alias(inode);
	if (!dentry) {
		return pathname;
	}
	(char *)kzalloc(sizeof(char) * MAX_PATHLEN, GFP_KERNEL);
	if (!pathname) {
		//dput(dentry);
		return pathname;
	}
	rc = __vfs_getxattr(
		dentry, inode, name, pathname,
		MAX_PATHLEN *
			sizeof(char)); //inode->i_op->getxattr(dentry,name,pathname,MAX_PATHLEN)
	if (rc > 0) {
		//dput(dentry);
		//printk("Pindown: I get the inode_policy:%s\n", pathname);
		return pathname;
	}
	/*
    else if(rc==-ERANGE){
      rc=__vfs_getxattr(dentry,inode,name,NULL,0);  //get the real size
      if(rc<0){
        dput(dentry);
        kzfree(pathname);
        pathname=NULL;
        return pathname;
      }
      kzfree(pathname);
      len=rc/sizeof(char);
      pathname=(char*)kzalloc(sizeof(char)*len,GFP_KERNEL);
      //error no memory
      if(!pathname){
        dput(dentry);
        return pathname;
      }
      rc=__vfs_getxattr(dentry,inode,name,pathname,len*sizeof(char));
      dput(dentry);
      if(rc>=0){
        return pathname;
      }
      else{
        kzfree(pathname);
        pathname=NULL;
        return pathname;
      }

    }
    */
	else {
		//dput(dentry);
		kzfree(pathname);
		pathname = NULL;
		return pathname;
	}
}
static int pindown_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct pindown_security_t *tsec;
	//printk("Pindown: call cred_alloc_blank,count=%llu\n", ++count2);
	tsec = (pindown_security_t *)kzalloc(sizeof(struct pindown_security_t),
					     gfp);
	if (!tsec) {
		return -ENOMEM;
	}
	cred->security = tsec;
	return 0;
}

static int pindown_cred_alloc(struct cred *cred, gfp_t gfp)
{
	struct pindown_security_t *tsec;
	if (!cred) {
		return -ENOMEM;
	}
	//printk("Pindown: call cred_alloc\n");
	tsec = (pindown_security_t *)kzalloc(sizeof(struct pindown_security_t),
					     gfp);
	if (!tsec) {
		return -ENOMEM;
	}
	cred->security = tsec;
	return 0;
}

static void pindown_cred_transfer(struct cred *new, const struct cred *old)
{
	struct pindown_security_t *old_tsp = old->security;
	struct pindown_security_t *new_tsp = new->security;

	strcpy(new_tsp->bprm_pathname, old_tsp->bprm_pathname);
	new_tsp->pathlen = old_tsp->pathlen;

	/* cbs copy rule list */
}

int pindown_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	struct pindown_security_t *old_tsp = old->security;
	struct pindown_security_t *new_tsp;
	int len;
	new_tsp = (pindown_security_t *)kzalloc(
		sizeof(struct pindown_security_t), gfp);
	old_tsp = (pindown_security_t *)old->security;
	if (!new_tsp) {
		return -ENOMEM;
	}
	//printk("Pindown: call cred_prepare,count=%llu\n", ++count2);

	if (!old_tsp || !old_tsp->bprm_pathname) {
		new_tsp->bprm_pathname[0] = '\0';
		new_tsp->pathlen = 0;
		return 0;
	}

	len = strlen(old_tsp->bprm_pathname);
	if (len < MAX_PATHLEN) {
		strcpy(new_tsp->bprm_pathname, old_tsp->bprm_pathname);
		new_tsp->pathlen = len;
	} else {
		new_tsp->bprm_pathname[0] = '\0';
		new_tsp->pathlen = 0;
		return -ENOMEM;
	}
	new->security = new_tsp;

	return 0;
}

void pindown_cred_free(struct cred *cred)
{
	/*printk("ZhangXin's demo: call pindown_cred_free\n");
	if(!cred){
	    return;
	}
	*/
	struct pindown_security_t *tsp = (pindown_security_t *)cred->security;
	if (tsp == NULL) {
		return;
	}

	cred->security = NULL;
	kzfree(tsp); //In fact,it is security to call kzfree(NULL),too.

	return;
}


int pindown_inode_permission2(struct inode *inode, int mask)
{
	return 0;
}
int pindown_inode_permission(struct inode *inode, int mask)
{
	//Initial default allow. Change to default deny once implemented
	pindown_security_t *sec = NULL;
	char *inode_policy = NULL; //string used to stroe the policy.
	int rc;
	//Don't check this if it is a directory.
	if ((inode->i_mode & S_IFMT) == S_IFDIR) {
		return 0;
	}
	//get the file's xattr "security.pindown"
	inode_policy = get_inode_policy(inode, "security.pindown");
	if (!inode_policy) {
		//printk("Pindown: No inode_policy");
		return 0;
	}

	//Get the process security info.
	sec = current->cred->security;
	if (!sec || sec->bprm_pathname[0] == '\0') {
		//Do not allow a program to access a file if the program has not set the security field.

		//printk(KERN_INFO
		       "Pindown ERROR the inode_policy is %s  [ERRO:-EACCES]\n",
		       inode_policy);
		kzfree(inode_policy);
		//inode_policy = NULL;
		return 0; //-EACCES
	}
  
	rc = strcmp(sec->bprm_pathname, inode_policy);
  //if equal(return 0), allow the access
	if (!rc) {
		printk(KERN_INFO
		       "Pindown LSM check of %s allowing access,the inode policy is %s",
		       sec->bprm_pathname, inode_policy);
		kzfree(inode_policy);
		//inode_policy = NULL;
		return 0;
	} else {
		printk(KERN_INFO
		       "Pindown LSM check of %s denying access,the inode policy is %s",
		       sec->bprm_pathname, inode_policy);
		kzfree(inode_policy);
		//inode_policy = NULL;
		return 0; //-EACCES
	}
}
/* Function: pindown_bprm_set_creds(@bprm)
 * Description:
 *  - LSM Hook .bprm_set_creds()
 *  - Sets @current->security to the path of the binary
 * Input:
 *  @bprm   : pointer to a binary being loaded by the kernel
 * Output:
 *  - set @current->security to the path of the binary
 *  - return 0 if the hook is successful and permission is granted
 */
int pindown_bprm_set_creds2(struct linux_binprm *bprm)
{
	return 0;
}
int pindown_bprm_set_creds(
	struct linux_binprm
		*bprm) //bprm used by exec_binprm(bprm) to load a exe file
{
	//struct dentry *dentry = bprm->file->f_path.dentry;
	//struct inode *inode = d_backing_inode(dentry);
	struct pindown_security_t *bsp = bprm->cred->security;
	int rc = 0;
	//printk(KERN_INFO "ZhangXin's demo call:pindown_bprm_set_security.\n");
	if (bprm->called_set_creds) //True after the bprm_set_creds hook has been called once
		 return 0;
	//printk("Pindown: I'm tring to set creds for %s\n",bprm->filename);
	if (bsp == NULL) {
    /*
		rc = pindown_cred_alloc(bprm->cred, GFP_KERNEL_ACCOUNT);
		if (rc) {
			return rc;
		}*/
    return 0;
	}

	if (!bprm || !bprm->filename) {
		bsp->bprm_pathname[0] = '\0';
		return 0;
		//sec->pathlen=0;
	}
	//printk(KERN_INFO "ZhangXin's demo: BINARY %s.\n",bprm->filename);
	if (strlen(bprm->filename) < MAX_PATHLEN) {
    strcpy(bsp->bprm_pathname, bprm->filename);
    return 0;
	}
	bsp->bprm_pathname[0] = '\0';

	// if(sec->pathlen>=MAX_PATHLEN){
	//   rc=-ENOMEM;
	//  }

	return 0;
}

//在LSM框架下，每个安全模块需要实现一个"security_hook_list"结构体数组，每个数组项表示一个实现了的hook函数。
//此pindown中只实现了一个hook函数,所以结构体仅含一项。
//#define LSM_HOOK_INIT(HEAD, HOOK) { .head = &security_hook_heads.HEAD, .hook = { .HEAD = HOOK } }
static struct security_hook_list pindown_hooks[] = {
	LSM_HOOK_INIT(cred_free, pindown_cred_free),
	LSM_HOOK_INIT(cred_transfer, pindown_cred_transfer),
	LSM_HOOK_INIT(cred_alloc_blank, pindown_cred_alloc_blank),
	LSM_HOOK_INIT(cred_prepare, pindown_cred_prepare),
	LSM_HOOK_INIT(bprm_set_creds, pindown_bprm_set_creds),
	LSM_HOOK_INIT(inode_permission, pindown_inode_permission),

};

//将pindown_hooks添加到在security_hook_list的数据结构里
//例如：将pindown_hooks[0]添加到security_hook_list--->task_alloc（链表）->...->尾部。
void __init pindown_add_hooks(void)
{
	pr_info("pindown: becoming mindful.\n"); //打印相关信息，可以通过dmesg |  grep Yama:查看
	security_add_hooks(pindown_hooks, ARRAY_SIZE(pindown_hooks),
			   "pindown"); //添加安全模块函数
}

//对这个有注册逻辑的函数进行注册
static __init int pindown_init(void)
{
	pindown_add_hooks();
	return 0;
}

//
security_initcall(pindown_init);