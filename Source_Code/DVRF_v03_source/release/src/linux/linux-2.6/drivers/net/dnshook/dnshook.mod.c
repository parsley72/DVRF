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
	{ 0x349cba85, "strchr" },
	{ 0x97255bdf, "strlen" },
	{ 0x956ffca5, "ip_route_output_key" },
	{ 0x79aa04a2, "get_random_bytes" },
	{ 0xc1b4bd87, "malloc_sizes" },
	{ 0x89780147, "skb_copy" },
	{ 0x7d11c268, "jiffies" },
	{ 0x2bc95bd4, "memset" },
	{ 0xc0855fe9, "skb_checksum" },
	{ 0x8d3894f2, "_ctype" },
	{ 0xdd132261, "printk" },
	{ 0x71c90087, "memcmp" },
	{ 0x1e6d26a8, "strstr" },
	{ 0xcd360d1a, "cpu_data" },
	{ 0xa0c05cd9, "ip6_route_output" },
	{ 0xc4e2f61f, "skb_over_panic" },
	{ 0x3ff62317, "local_bh_disable" },
	{ 0xde1ebd5e, "kmem_cache_alloc" },
	{ 0xf2f0123c, "ipv6_skip_exthdr" },
	{ 0x76707e9a, "kfree_skb" },
	{ 0x6b2dc060, "dump_stack" },
	{ 0x799aca4, "local_bh_enable" },
	{ 0xa7e43df6, "skb_under_panic" },
	{ 0xd83791bc, "nf_conntrack_destroy" },
	{ 0xf6ebc03b, "net_ratelimit" },
	{ 0x37a0cba, "kfree" },
	{ 0x11f7ce5e, "memcpy" },
	{ 0x25da070, "snprintf" },
	{ 0xe113bbbc, "csum_partial" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "AE0497B6E222012CF88AE81");
