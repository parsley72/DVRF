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
	{ 0x72216fa9, "param_get_uint" },
	{ 0x8abac70a, "param_set_uint" },
	{ 0x79842f9d, "nf_conntrack_unexpect_related" },
	{ 0x90f30fd9, "nf_conntrack_expect_put" },
	{ 0xd65c9b84, "nf_conntrack_expect_related" },
	{ 0x8d3d558b, "nf_conntrack_expect_init" },
	{ 0x2fd74ab2, "nf_conntrack_expect_alloc" },
	{ 0x20000329, "simple_strtoul" },
	{ 0xaccabc6a, "in4_pton" },
	{ 0x71c90087, "memcmp" },
	{ 0x1d26aa98, "sprintf" },
	{ 0x1a13be01, "ct_sip_get_info" },
	{ 0x97255bdf, "strlen" },
	{ 0x3835c6ee, "ct_sip_get_sdp_header" },
	{ 0xa91aae3d, "nf_nat_mangle_udp_packet" },
	{ 0x25da070, "snprintf" },
	{ 0xa9630e28, "nf_nat_setup_info" },
	{ 0x6091797f, "synchronize_rcu" },
	{ 0xd7ed22b7, "nf_nat_sdp_media_hook" },
	{ 0xeae9449c, "nf_nat_sdp_session_hook" },
	{ 0xb2a8eebf, "nf_nat_sdp_port_hook" },
	{ 0x793a207d, "nf_nat_sdp_addr_hook" },
	{ 0xe7714a91, "nf_nat_sip_hook" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=nf_conntrack_sip";


MODULE_INFO(srcversion, "F526103FDED3DF33F5D45F1");
