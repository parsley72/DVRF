#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__attribute_used__
__attribute__((section("__versions"))) = {
	{ 0xf531d0bc, "struct_module" },
	{ 0x9a1dfd65, "strpbrk" },
	{ 0x89480c9d, "osl_delay" },
	{ 0x349cba85, "strchr" },
	{ 0x97255bdf, "strlen" },
	{ 0x110e2600, "remove_proc_entry" },
	{ 0x1d26aa98, "sprintf" },
	{ 0xb6091ec0, "__copy_user" },
	{ 0x2bc95bd4, "memset" },
	{ 0xdd132261, "printk" },
	{ 0xc777ca5a, "si_setcore" },
	{ 0x7d49052b, "create_proc_entry" },
	{ 0x14540e95, "si_setcoreidx" },
	{ 0xe5729660, "proc_root" },
	{ 0x6334f7c, "si_kattach" },
	{ 0x4d0521c4, "si_osh" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "EEAAD9F38B33EB2273ECF79");
