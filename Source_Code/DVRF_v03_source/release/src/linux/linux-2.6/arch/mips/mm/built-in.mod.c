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
	{ 0x350e2f4, "up_read" },
	{ 0xf70828b, "page_address" },
	{ 0x55d0acc9, "init_mm" },
	{ 0x1139ffc, "max_mapnr" },
	{ 0x5ebb56fb, "down_read" },
	{ 0xde9360ba, "totalram_pages" },
	{ 0x2bc95bd4, "memset" },
	{ 0xdd132261, "printk" },
	{ 0x1075bf0, "panic" },
	{ 0x948cde9, "num_physpages" },
	{ 0x4164a9cd, "mem_section" },
	{ 0xd5657664, "kunmap_high" },
	{ 0xcd360d1a, "cpu_data" },
	{ 0x5080386b, "do_exit" },
	{ 0x59a0698a, "contig_page_data" },
	{ 0xb98ef804, "vm_stat" },
	{ 0x18a86787, "__handle_mm_fault" },
	{ 0x1ffba645, "find_vma" },
	{ 0xca774c95, "__free_pages" },
	{ 0x93fca811, "__get_free_pages" },
	{ 0x8a7d1c31, "high_memory" },
	{ 0xb4fb2287, "shm_align_mask" },
	{ 0x4302d0eb, "free_pages" },
	{ 0x37a0cba, "kfree" },
	{ 0xe7ead430, "vunmap" },
	{ 0x11f7ce5e, "memcpy" },
	{ 0x96f2a8b6, "kmap_high" },
	{ 0x760a0f4f, "yield" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=built-in,built-in,init_task,built-in";

