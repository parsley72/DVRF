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
	{ 0xf9a482f9, "msleep" },
	{ 0x8818ebcd, "netlink_has_listeners" },
	{ 0xc1b4bd87, "malloc_sizes" },
	{ 0x4c7b234a, "sock_release" },
	{ 0xfbea45e6, "queue_work" },
	{ 0x323222ba, "mutex_unlock" },
	{ 0x12f237eb, "__kzalloc" },
	{ 0xbeb32c43, "__create_workqueue" },
	{ 0xee200448, "netlink_kernel_create" },
	{ 0x2bc95bd4, "memset" },
	{ 0xdd132261, "printk" },
	{ 0xb97d4c9c, "mutex_lock" },
	{ 0x94aaeb94, "destroy_workqueue" },
	{ 0xcd360d1a, "cpu_data" },
	{ 0x35ada5b1, "flush_workqueue" },
	{ 0xc4e2f61f, "skb_over_panic" },
	{ 0x3ff62317, "local_bh_disable" },
	{ 0x6e139094, "__alloc_skb" },
	{ 0xa28d9456, "netlink_broadcast" },
	{ 0x72216fa9, "param_get_uint" },
	{ 0x76707e9a, "kfree_skb" },
	{ 0x799aca4, "local_bh_enable" },
	{ 0xbb20d859, "kmem_cache_zalloc" },
	{ 0x37a0cba, "kfree" },
	{ 0x11f7ce5e, "memcpy" },
	{ 0x8abac70a, "param_set_uint" },
	{ 0x2027ed1b, "skb_dequeue" },
	{ 0x25da070, "snprintf" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "1E260AFD1BEE0A1DFD89B4F");
