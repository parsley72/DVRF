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
	{ 0x40c705e7, "sigprocmask" },
	{ 0xf9a482f9, "msleep" },
	{ 0x70c66486, "ptrace_notify" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x5c3883ba, "per_cpu__kstat" },
	{ 0x1f9cfe83, "iomem_resource" },
	{ 0x55d0acc9, "init_mm" },
	{ 0xfd17e90b, "send_sig" },
	{ 0xc1b4bd87, "malloc_sizes" },
	{ 0x36e47222, "remove_wait_queue" },
	{ 0xaf225792, "seq_printf" },
	{ 0x3096be16, "names_cachep" },
	{ 0x2fd1d81c, "vfree" },
	{ 0xffd5a395, "default_wake_function" },
	{ 0xb56717cf, "xtime" },
	{ 0x7c60d66e, "getname" },
	{ 0xdf60cc27, "__print_symbol" },
	{ 0xdd132261, "printk" },
	{ 0x1075bf0, "panic" },
	{ 0xa8a4b244, "xtime_lock" },
	{ 0xe1dd1220, "seq_putc" },
	{ 0xa6a8dd49, "kmem_cache_free" },
	{ 0x897473df, "mktime" },
	{ 0x231cf494, "up_write" },
	{ 0xb3fe02b1, "down_write" },
	{ 0x1ecde35e, "fput" },
	{ 0x5080386b, "do_exit" },
	{ 0x59a0698a, "contig_page_data" },
	{ 0xaac2eab6, "do_mmap_pgoff" },
	{ 0xe269ea1c, "sys_open" },
	{ 0x8a1967e, "clocksource_register" },
	{ 0x1ffba645, "find_vma" },
	{ 0xde1ebd5e, "kmem_cache_alloc" },
	{ 0x1000e51, "schedule" },
	{ 0x30c3ef47, "set_irq_chip" },
	{ 0xfb6af58d, "recalc_sigpending" },
	{ 0x563c9c58, "force_sig" },
	{ 0xab762422, "wake_up_process" },
	{ 0xb6c70a7d, "__wake_up" },
	{ 0x37a0cba, "kfree" },
	{ 0x2efa450d, "sys_read" },
	{ 0x3e6caebd, "add_wait_queue_exclusive" },
	{ 0x5f865caf, "fget" },
	{ 0x9d43755c, "request_resource" },
	{ 0xdcb0349b, "sys_close" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=built-in,built-in,init_task,built-in";

