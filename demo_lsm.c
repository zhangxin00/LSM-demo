#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
/*
编写一个基于LSM的安全模块的基本流程：

1.确定需要hook的函数
2.对hook函数进行填充，添加自己的逻辑（安全检查）
3.添加到在security_hook_list的数据结构里
4.对这个有注册逻辑的函数进行注册

*/


/*

确定需要hook的函数：  ---task_alloc(),task_free()

*/

//对hook函数进行填充，添加自己的逻辑（安全检查）,这里让它输出一条内核信息。
static unsigned long long count = 0;

int demo_task_alloc(struct task_struct *task,unsigned long clone_flags)   //y
{
    printk("[ZhangXin's demo] call demo_task_alloc(). count=%llu\n", ++count);    
    return 0;
}
void demo_task_free (struct task_struct *task)
{
     printk("[ZhangXin's demo] call demo_task_free(). count=%llu\n", --count); 
}
//在LSM框架下，每个安全模块需要实现一个"security_hook_list"结构体数组，每个数组项表示一个实现了的hook函数。
//此demo中只实现了一个hook函数,所以结构体仅含一项。
//#define LSM_HOOK_INIT(HEAD, HOOK) { .head = &security_hook_heads.HEAD, .hook = { .HEAD = HOOK } }
static struct security_hook_list demo_hooks[] = {
    LSM_HOOK_INIT(task_alloc,demo_task_alloc),
    LSM_HOOK_INIT(task_free,demo_task_free),
    
};

/*struct security_hook_list {
	struct hlist_node		list;（用于侵入式链表）
	struct hlist_head		*head;
	union security_list_options	hook;
	char				*lsm;
} __randomize_layout;
*/

{
static struct security_hook_list demo2_hooks[2];
demo2_hooks[0].head=&security_hook_heads.task_alloc;   //security_hook_heads在security.c中实例化,要hook task_alloc
demo2_hooks[0].hook.task_alloc=demo_task_alloc;  //将要hook的task_create变成我们定义的demo_task_alloc
demo2_hooks[1].head=&security_hook_heads.task_free; 
demo2_hooks[1].hook.task_free=demo_task_free; 

}

//将demo_hooks添加到在security_hook_list的数据结构里
//例如：将demo_hooks[0]添加到security_hook_list--->task_alloc（链表）->...->尾部。
void __init demo_add_hooks(void)
{
    pr_info("Demo: becoming mindful.\n");        //打印相关信息，可以通过dmesg |  grep Yama:查看
    security_add_hooks(demo_hooks, ARRAY_SIZE(demo_hooks),"demo");   //添加安全模块函数
}

//对这个有注册逻辑的函数进行注册
static __init int demo_init(void){
    demo_add_hooks();
    return 0;
}

//
security_initcall(demo_init);