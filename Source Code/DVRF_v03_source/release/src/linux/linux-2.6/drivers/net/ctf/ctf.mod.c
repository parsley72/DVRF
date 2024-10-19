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
	{ 0xe033c832, "kcih" },
	{ 0x1e33e00, "getintvar" },
	{ 0xb85ff2a8, "osl_mfree" },
	{ 0xfb5f4ca1, "osl_pktfree" },
	{ 0x7d11c268, "jiffies" },
	{ 0x2bc95bd4, "memset" },
	{ 0xdd132261, "printk" },
	{ 0x71c90087, "memcmp" },
	{ 0x40a0ceb8, "ctf_attach_fn" },
	{ 0xcd360d1a, "cpu_data" },
	{ 0x3ff62317, "local_bh_disable" },
	{ 0x799aca4, "local_bh_enable" },
	{ 0xa7e43df6, "skb_under_panic" },
	{ 0x5c20b2f6, "osl_pkt_frmnative" },
	{ 0x11f7ce5e, "memcpy" },
	{ 0x58c774ac, "osl_malloc" },
	{ 0xe113bbbc, "csum_partial" },
	{ 0x2e42efe, "dev_queue_xmit" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";

