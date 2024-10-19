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
	{ 0x8c97a7db, "__vm_enough_memory" },
	{ 0xabe77484, "securebits" },
	{ 0xb694c524, "suid_dumpable" },
	{ 0x59ab4080, "cap_bset" },
	{ 0x68019236, "__capable" },
	{ 0x7dceceac, "capable" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=built-in,built-in,built-in";

