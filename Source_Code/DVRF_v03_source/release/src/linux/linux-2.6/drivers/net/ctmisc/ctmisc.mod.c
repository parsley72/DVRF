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
	{ 0x89480c9d, "osl_delay" },
	{ 0x97255bdf, "strlen" },
	{ 0xc1b4bd87, "malloc_sizes" },
	{ 0x1d26aa98, "sprintf" },
	{ 0xb6091ec0, "__copy_user" },
	{ 0xad905ae1, "misc_register" },
	{ 0x2bc95bd4, "memset" },
	{ 0x79870675, "nvram_get" },
	{ 0xdd132261, "printk" },
	{ 0x71c90087, "memcmp" },
	{ 0xc777ca5a, "si_setcore" },
	{ 0xde1ebd5e, "kmem_cache_alloc" },
	{ 0x14540e95, "si_setcoreidx" },
	{ 0x37a0cba, "kfree" },
	{ 0x11f7ce5e, "memcpy" },
	{ 0x6334f7c, "si_kattach" },
	{ 0x4d0521c4, "si_osh" },
	{ 0xaab1b206, "misc_deregister" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "04748168264C473F1185DE2");
