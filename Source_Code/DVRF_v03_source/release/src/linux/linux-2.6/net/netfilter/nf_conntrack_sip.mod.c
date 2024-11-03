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
	{ 0xfe823460, "nf_conntrack_helper_register" },
	{ 0xd8b20fc5, "__nf_ct_refresh_acct" },
	{ 0x9d803cd8, "nf_conntrack_helper_unregister" },
	{ 0x79842f9d, "nf_conntrack_unexpect_related" },
	{ 0x20000329, "simple_strtoul" },
	{ 0x806d5133, "param_array_get" },
	{ 0x4e830a3e, "strnicmp" },
	{ 0x1d26aa98, "sprintf" },
	{ 0x89cef6fb, "param_array_set" },
	{ 0xdb29de71, "nf_conntrack_expect_find_by_sip_call_id" },
	{ 0xc50564f2, "ip_dev_find" },
	{ 0xd9cb3de9, "__pskb_pull_tail" },
	{ 0xd65c9b84, "nf_conntrack_expect_related" },
	{ 0x2bc95bd4, "memset" },
	{ 0x8d3894f2, "_ctype" },
	{ 0x90f30fd9, "nf_conntrack_expect_put" },
	{ 0xdd132261, "printk" },
	{ 0x71c90087, "memcmp" },
	{ 0xcd360d1a, "cpu_data" },
	{ 0x8d3d558b, "nf_conntrack_expect_init" },
	{ 0x5418d52a, "param_get_ushort" },
	{ 0x72216fa9, "param_get_uint" },
	{ 0xaccabc6a, "in4_pton" },
	{ 0x2fd74ab2, "nf_conntrack_expect_alloc" },
	{ 0x11f7ce5e, "memcpy" },
	{ 0x8abac70a, "param_set_uint" },
	{ 0xe57878a1, "in6_pton" },
	{ 0x25da070, "snprintf" },
	{ 0xc4c5509d, "param_set_ushort" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "B5DFB12ACDF74459C2618E0");
