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
	{ 0xf9a482f9, "msleep" },
	{ 0x6b1b67d3, "__bdevname" },
	{ 0xd153e110, "find_task_by_pid_type" },
	{ 0xc893a239, "ktime_get" },
	{ 0x3096be16, "names_cachep" },
	{ 0x5a4dac68, "cpu_present_map" },
	{ 0x7d11c268, "jiffies" },
	{ 0xdf60cc27, "__print_symbol" },
	{ 0xdd132261, "printk" },
	{ 0x1075bf0, "panic" },
	{ 0xf95f50c7, "cad_pid" },
	{ 0xa6a8dd49, "kmem_cache_free" },
	{ 0x948cde9, "num_physpages" },
	{ 0xcd360d1a, "cpu_data" },
	{ 0xe269ea1c, "sys_open" },
	{ 0x888596d, "cpu_possible_map" },
	{ 0xb306c8ad, "cpu_online_map" },
	{ 0xde1ebd5e, "kmem_cache_alloc" },
	{ 0x1000e51, "schedule" },
	{ 0x801678, "flush_scheduled_work" },
	{ 0x2efa450d, "sys_read" },
	{ 0x7ca341af, "kernel_thread" },
	{ 0xaa39f95c, "memmove" },
	{ 0xdcb0349b, "sys_close" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=built-in,built-in,built-in,built-in";

