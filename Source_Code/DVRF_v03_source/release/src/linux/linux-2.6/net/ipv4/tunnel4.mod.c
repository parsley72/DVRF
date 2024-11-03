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
	{ 0x609f1c7e, "synchronize_net" },
	{ 0xfb3c2e91, "icmp_send" },
	{ 0x323222ba, "mutex_unlock" },
	{ 0x487f8262, "inet_del_protocol" },
	{ 0xd9cb3de9, "__pskb_pull_tail" },
	{ 0xdd132261, "printk" },
	{ 0xb97d4c9c, "mutex_lock" },
	{ 0x1ae62515, "inet_add_protocol" },
	{ 0x76707e9a, "kfree_skb" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "61F74848E8308291FD2C6D3");
