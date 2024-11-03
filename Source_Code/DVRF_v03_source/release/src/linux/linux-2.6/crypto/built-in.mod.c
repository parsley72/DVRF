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
	{ 0x4d125935, "__kmap_atomic" },
	{ 0x350e2f4, "up_read" },
	{ 0x43ef93b9, "seq_open" },
	{ 0xc1b4bd87, "malloc_sizes" },
	{ 0xaf225792, "seq_printf" },
	{ 0x110e2600, "remove_proc_entry" },
	{ 0xb4a4b9fb, "blocking_notifier_chain_unregister" },
	{ 0xa3070522, "seq_read" },
	{ 0x5ebb56fb, "down_read" },
	{ 0xda4008e6, "cond_resched" },
	{ 0x12f237eb, "__kzalloc" },
	{ 0x2bc95bd4, "memset" },
	{ 0xdd132261, "printk" },
	{ 0xe1dd1220, "seq_putc" },
	{ 0x4164a9cd, "mem_section" },
	{ 0xbc7d49dc, "__kunmap_atomic" },
	{ 0xcd360d1a, "cpu_data" },
	{ 0x231cf494, "up_write" },
	{ 0xb3fe02b1, "down_write" },
	{ 0x83a1f4fd, "module_put" },
	{ 0xd741cfcf, "blocking_notifier_call_chain" },
	{ 0x6b2dc060, "dump_stack" },
	{ 0x8d5642fc, "wait_for_completion_interruptible_timeout" },
	{ 0x7d49052b, "create_proc_entry" },
	{ 0xdc68ea3a, "__module_put_and_exit" },
	{ 0xab762422, "wake_up_process" },
	{ 0x98196f5b, "blocking_notifier_chain_register" },
	{ 0x6cb34e5, "init_waitqueue_head" },
	{ 0xbb20d859, "kmem_cache_zalloc" },
	{ 0x7a51e246, "seq_lseek" },
	{ 0x37a0cba, "kfree" },
	{ 0x53f4e604, "kthread_create" },
	{ 0x11f7ce5e, "memcpy" },
	{ 0x98adfde2, "request_module" },
	{ 0x6412dbfe, "__flush_dcache_page" },
	{ 0xa218bf61, "complete" },
	{ 0xdead8401, "seq_release" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=built-in,built-in,built-in,built-in,built-in";

