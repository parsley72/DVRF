#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__attribute_used__
__attribute__((section("__versions"))) = {
	{ 0xf531d0bc, "struct_module" },
	{ 0x7008a9b7, "timespec_to_jiffies" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x88635bb7, "register_sysctl_table" },
	{ 0x43ef93b9, "seq_open" },
	{ 0x4af3cf7a, "seq_release_private" },
	{ 0xc1b4bd87, "malloc_sizes" },
	{ 0xf7af0c84, "seq_puts" },
	{ 0x9e911bf1, "proc_dointvec" },
	{ 0xc633495b, "schedule_work" },
	{ 0xb2643240, "dput" },
	{ 0xaf225792, "seq_printf" },
	{ 0x323222ba, "mutex_unlock" },
	{ 0x2fd1d81c, "vfree" },
	{ 0x1251d30f, "call_rcu" },
	{ 0xa3070522, "seq_read" },
	{ 0x12f237eb, "__kzalloc" },
	{ 0xb6091ec0, "__copy_user" },
	{ 0x2bc95bd4, "memset" },
	{ 0xb56717cf, "xtime" },
	{ 0x6c36a5c1, "__mutex_init" },
	{ 0xdd132261, "printk" },
	{ 0xa12aab4c, "proc_doulongvec_minmax" },
	{ 0xb97d4c9c, "mutex_lock" },
	{ 0xcd360d1a, "cpu_data" },
	{ 0x231cf494, "up_write" },
	{ 0xb3fe02b1, "down_write" },
	{ 0x1ecde35e, "fput" },
	{ 0xaac2eab6, "do_mmap_pgoff" },
	{ 0x1ffba645, "find_vma" },
	{ 0x7dceceac, "capable" },
	{ 0xde1ebd5e, "kmem_cache_alloc" },
	{ 0xdacc0b2a, "mntput_no_expire" },
	{ 0x629640e2, "do_munmap" },
	{ 0x1000e51, "schedule" },
	{ 0xd62c833f, "schedule_timeout" },
	{ 0xc3cf1128, "in_group_p" },
	{ 0x7d49052b, "create_proc_entry" },
	{ 0xab762422, "wake_up_process" },
	{ 0xbb20d859, "kmem_cache_zalloc" },
	{ 0x5eda67b3, "get_unmapped_area" },
	{ 0x7a51e246, "seq_lseek" },
	{ 0x37a0cba, "kfree" },
	{ 0x11f7ce5e, "memcpy" },
	{ 0x4263d6ed, "get_empty_filp" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=built-in,built-in,built-in,built-in";

