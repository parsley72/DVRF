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
	{ 0x1a2f395c, "osl_pktdup" },
	{ 0xb85ff2a8, "osl_mfree" },
	{ 0x4c7b234a, "sock_release" },
	{ 0xfb5f4ca1, "osl_pktfree" },
	{ 0x72e57b7d, "dev_get_by_name" },
	{ 0x110e2600, "remove_proc_entry" },
	{ 0x165f88c7, "nf_register_hook" },
	{ 0x1d26aa98, "sprintf" },
	{ 0xba77e24b, "netif_rx" },
	{ 0xee200448, "netlink_kernel_create" },
	{ 0x2bc95bd4, "memset" },
	{ 0xdd132261, "printk" },
	{ 0x8468a9c1, "osl_attach" },
	{ 0xb6a2cf40, "netlink_unicast" },
	{ 0xcd360d1a, "cpu_data" },
	{ 0x3ff62317, "local_bh_disable" },
	{ 0x76707e9a, "kfree_skb" },
	{ 0x799aca4, "local_bh_enable" },
	{ 0xa7e43df6, "skb_under_panic" },
	{ 0x7d49052b, "create_proc_entry" },
	{ 0x1ec12ca0, "bcm_binit" },
	{ 0x78c1ab7, "bcm_bprintf" },
	{ 0x8d24031f, "nf_unregister_hook" },
	{ 0x1eda5758, "osl_detach" },
	{ 0x11f7ce5e, "memcpy" },
	{ 0x2027ed1b, "skb_dequeue" },
	{ 0x58c774ac, "osl_malloc" },
	{ 0x2e42efe, "dev_queue_xmit" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";

