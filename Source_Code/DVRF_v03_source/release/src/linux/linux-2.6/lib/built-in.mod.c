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
	{ 0x12da5bb2, "__kmalloc" },
	{ 0x6231f14e, "pci_release_region" },
	{ 0xe911fb89, "devres_get" },
	{ 0xda7082ab, "devres_find" },
	{ 0x79aa04a2, "get_random_bytes" },
	{ 0xe93e49c3, "devres_free" },
	{ 0x7d11c268, "jiffies" },
	{ 0xfc39e32f, "ioport_unmap" },
	{ 0xbab04013, "pci_iounmap" },
	{ 0xdd132261, "printk" },
	{ 0xf935d2dd, "devres_alloc" },
	{ 0xcd360d1a, "cpu_data" },
	{ 0xacf2df89, "__ioremap" },
	{ 0xb1c3a01a, "oops_in_progress" },
	{ 0x594bf15b, "ioport_map" },
	{ 0x6b2dc060, "dump_stack" },
	{ 0x2d7aa795, "devres_add" },
	{ 0x37a0cba, "kfree" },
	{ 0x11f7ce5e, "memcpy" },
	{ 0xe3c1a49f, "devres_destroy" },
	{ 0x60247532, "__iounmap" },
	{ 0x709c3a40, "pci_iomap" },
	{ 0xb56ab77f, "pci_request_region" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=built-in,built-in,built-in,built-in,built-in,built-in";

