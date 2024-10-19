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
	{ 0xd34d672c, "ip_route_input" },
	{ 0x956ffca5, "ip_route_output_key" },
	{ 0xcc931bf7, "skb_clone" },
	{ 0xc6bdfef3, "netdev_state_change" },
	{ 0xb6091ec0, "__copy_user" },
	{ 0x7dceceac, "capable" },
	{ 0xfb3c2e91, "icmp_send" },
	{ 0x6c8e9f9c, "icmpv6_send" },
	{ 0xa7e43df6, "skb_under_panic" },
	{ 0xa0c05cd9, "ip6_route_output" },
	{ 0x4a87f399, "nf_hook_slow" },
	{ 0xa956f95, "nf_hooks" },
	{ 0x9cbe0883, "ipv6_push_nfrag_opts" },
	{ 0x494c3b0c, "sock_wfree" },
	{ 0x4879faf2, "skb_realloc_headroom" },
	{ 0xd5377e8, "__dev_get_by_name" },
	{ 0xba358f53, "register_netdevice" },
	{ 0x73e20c1c, "strlcpy" },
	{ 0x1d26aa98, "sprintf" },
	{ 0xf35a972e, "rt6_lookup" },
	{ 0xd542439, "__ipv6_addr_type" },
	{ 0x11f7ce5e, "memcpy" },
	{ 0x799aca4, "local_bh_enable" },
	{ 0x3ff62317, "local_bh_disable" },
	{ 0xeecf1313, "register_netdev" },
	{ 0x650b5562, "alloc_netdev" },
	{ 0x88089103, "xfrm6_tunnel_register" },
	{ 0x6e720ff2, "rtnl_unlock" },
	{ 0x64123b8c, "unregister_netdevice" },
	{ 0xc7a4fbed, "rtnl_lock" },
	{ 0x2532dd13, "xfrm6_tunnel_deregister" },
	{ 0x6b2dc060, "dump_stack" },
	{ 0xba77e24b, "netif_rx" },
	{ 0xd83791bc, "nf_conntrack_destroy" },
	{ 0x2bc95bd4, "memset" },
	{ 0x8350286a, "ipv6_chk_addr" },
	{ 0x849c34e4, "dev_get_by_index" },
	{ 0x76707e9a, "kfree_skb" },
	{ 0xdd132261, "printk" },
	{ 0xf6ebc03b, "net_ratelimit" },
	{ 0xd9cb3de9, "__pskb_pull_tail" },
	{ 0x8e0b7743, "ipv6_ext_hdr" },
	{ 0xcd360d1a, "cpu_data" },
	{ 0xf360ce54, "free_netdev" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=tunnel6";


MODULE_INFO(srcversion, "310CAD8B5066CA8B7351535");
