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
	{ 0x57da4815, "pci_bus_read_config_byte" },
	{ 0x1f9cfe83, "iomem_resource" },
	{ 0x6402aaff, "release_resource" },
	{ 0xf70828b, "page_address" },
	{ 0x2767aa8b, "_dma_cache_wback_inv" },
	{ 0xb407b205, "ioport_resource" },
	{ 0xdd132261, "printk" },
	{ 0x4164a9cd, "mem_section" },
	{ 0x1a98fa32, "pci_bus_write_config_byte" },
	{ 0x9d43755c, "request_resource" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=built-in,built-in,built-in,built-in";

