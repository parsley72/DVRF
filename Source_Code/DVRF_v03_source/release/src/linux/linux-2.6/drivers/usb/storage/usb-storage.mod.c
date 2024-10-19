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
	{ 0xab1d73b1, "usb_buffer_alloc" },
	{ 0x8e9eceaa, "complete_and_exit" },
	{ 0x88635bb7, "register_sysctl_table" },
	{ 0xee576b5c, "scsi_host_alloc" },
	{ 0x33a768b6, "usb_sg_wait" },
	{ 0x97255bdf, "strlen" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x78c0ffec, "__down_interruptible" },
	{ 0xffaf7bbb, "__wake_up_sync" },
	{ 0xc1b4bd87, "malloc_sizes" },
	{ 0x9e911bf1, "proc_dointvec" },
	{ 0xb6e37825, "blk_queue_max_sectors" },
	{ 0xb1a3f68c, "usb_buffer_free" },
	{ 0x48d47095, "usb_kill_urb" },
	{ 0xa8ab48a8, "usb_led_flag" },
	{ 0x323222ba, "mutex_unlock" },
	{ 0x3fe5fc36, "__up" },
	{ 0x1d26aa98, "sprintf" },
	{ 0xce8380dc, "usb_unlink_urb" },
	{ 0xfc613daa, "usb_led_queue" },
	{ 0x25fa6f17, "wait_for_completion" },
	{ 0x2bc95bd4, "memset" },
	{ 0x174692de, "usb_lock_device_for_reset" },
	{ 0xe20b2c69, "usb_deregister" },
	{ 0x6c36a5c1, "__mutex_init" },
	{ 0xdd132261, "printk" },
	{ 0x859204af, "sscanf" },
	{ 0x93766d1b, "scsi_add_host" },
	{ 0x1a2c4d6f, "scsi_scan_host" },
	{ 0xb97d4c9c, "mutex_lock" },
	{ 0xcd360d1a, "cpu_data" },
	{ 0xcbf2cee7, "__kunmap" },
	{ 0xf01f234e, "scsi_host_put" },
	{ 0x382edc4a, "usb_submit_urb" },
	{ 0xde1ebd5e, "kmem_cache_alloc" },
	{ 0x7d600e9e, "scsi_host_get" },
	{ 0x22562832, "unregister_sysctl_table" },
	{ 0x72216fa9, "param_get_uint" },
	{ 0xd62c833f, "schedule_timeout" },
	{ 0x49ecc85d, "usb_sg_cancel" },
	{ 0x8d5642fc, "wait_for_completion_interruptible_timeout" },
	{ 0xab762422, "wake_up_process" },
	{ 0x6cb34e5, "init_waitqueue_head" },
	{ 0xb6c70a7d, "__wake_up" },
	{ 0x37a0cba, "kfree" },
	{ 0x53f4e604, "kthread_create" },
	{ 0x11f7ce5e, "memcpy" },
	{ 0x8085c7b1, "prepare_to_wait" },
	{ 0x6fa7f6f3, "usb_reset_composite_device" },
	{ 0x8abac70a, "param_set_uint" },
	{ 0x3dab08e8, "blk_queue_dma_alignment" },
	{ 0x36d5de3a, "usb_sg_init" },
	{ 0x6dbefa61, "scsi_report_bus_reset" },
	{ 0x9e1ed2a7, "usb_register_driver" },
	{ 0x51493d94, "finish_wait" },
	{ 0xf9d03bf6, "scsi_remove_host" },
	{ 0xa218bf61, "complete" },
	{ 0x152e0feb, "__kmap" },
	{ 0x5e225026, "usb_free_urb" },
	{ 0x9b82dfd5, "scsi_report_device_reset" },
	{ 0xb9f3d096, "usb_alloc_urb" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";

MODULE_ALIAS("usb:v03EBp2002d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v03EEp6901d0200dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v03EEp6901d0[0-1]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v03EEp6906d0003dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v03F0p0107d0200dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0409p0040d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v040Dp6205d0003dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0411p001Cd0113dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0419p0100d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0419pAACEd0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0419pAAF5d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0419pAAF6d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0420p0001d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0421p0019d0592dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0421p042Ed0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0421p0433d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0421p0434d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0421p0444d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0421p0446d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0421p044Ed0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0421p047Cd0370dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0421p0492d0452dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0421p0495d0370dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0424p0FDCd0210dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0451p5416d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0457p0150d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0457p0151d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v046BpFF40d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0482p0100d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0482p0101d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0482p0103d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04A4p0004d0001dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04B0p0301d0010dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04B0p0405d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04B0p040Dd0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04B0p0411d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04A5p3010d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04B8p0601d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04B8p0602d0110dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04CBp0100d2210dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04CBp0100d220*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04CBp0100d2[0-1]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04CBp0100d[0-1]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04CEp0002d0074dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04DAp0901d0200dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04DAp0901d01*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04DAp0D05d0000dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04DAp2372d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04DAp2373d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04E6p0001d0200dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04E6p0002d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04E6p0006d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04E6p0006d0205dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04E6p0007d0200dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04E6p0007d01*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04E6p0009d0200dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04E6p000Ad0200dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04E6p000Bd0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04E6p000Cd0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04E6p0101d0200dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v04FCp80C2d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v050Dp0115d0133dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0525pA140d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v052Bp1801d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v052Bp1804d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v052Bp1807d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v052Bp1905d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v052Bp1911d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp0010d010[6-9]dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp0010d0450dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp0010d01[1-9]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp0010d04[0-4]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp0010d0[2-3]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp0010d0610dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp0010d060*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp0010d05*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp0025d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp002Cd050[1-9]dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp002Cd2000dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp002Cd05[1-9]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp002Cd0[6-9]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp002Cd1*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp002Dd0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp002Ed010[6-9]dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp002Ed0310dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp002Ed01[1-9]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp002Ed030*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp002Ed02*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp002Ed0500dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp0032d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp0058d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp0069d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp006Dd*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp016Ad*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v054Cp0099d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v055Dp2020d0210dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v055Dp2020d020*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v055Dp2020d0[0-1]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v057Bp0000d0[0-2]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v057Bp0000d0[3-9]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v057Bp0000d[1-9]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v057Bp0022d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0595p4343d2210dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0595p4343d220*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0595p4343d2[0-1]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0595p4343d[0-1]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v059Fp0643d0000dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v05ABp0060d110[4-9]dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v05ABp0060d1110dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v05ACp1202d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v05ACp1203d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v05ACp1204d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v05ACp1205d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v05ACp120Ad*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v05DCpB002d011[0-3]dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v05DCpB002d010*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v05DCpB002d00*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v05E3p0701d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v05E3p0702d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0636p0003d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0644p0000d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v066Fp8000d0001dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v067Bp2507d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v067Bp3507d0001dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0686p4011d0001dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0686p4017d0001dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0693p0005d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v069Bp3004d0001dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0727p0306d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0781p0001d0200dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0781p0002d0009dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0781p0100d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v07ABpFCCDd*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v07AFp0004d013[0-3]dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v07AFp0004d01[0-2]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v07AFp0005d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v07C4pA400d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v07CFp1001d[1-9]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0839p000Ad0001dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v084Dp0011d0110dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v08BDp1100d0000dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v08CAp3103d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v090Ap1001d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v090Ap1050d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v090Ap1200d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v090Cp1132d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0A17p0004d1000dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0A17p0006d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0ACEp2011d0101dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0ACEp20FFd0101dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0781p5406d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0C45p1060d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0D96p410Ad000[1-9]dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0D96p410Ad00[1-9]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0D96p410Ad0[1-9]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0D96p410Ad[1-9]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0D96p5200d000[1-9]dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0D96p5200d0200dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0D96p5200d00[1-9]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0D96p5200d01*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0DD8p1060d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0DD8pD202d*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0DDAp0001d0012dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0DDAp0301d0012dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0E21p0520d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0ED1p6660d0300dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0ED1p6660d0[1-2]*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0EA0p2168d0110dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0EA0p6828d0110dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0ED1p7636d0103dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0F19p0105d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0FCEpD008d0000dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0FCEpE030d0000dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v0FCEpE031d0000dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v1019p0C55d0110dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v1019p0C55d010*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v1019p0C55d00*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v1210p0003d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v132Bp000Bd0001dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v1370p6828d0110dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v14CDp6600d0201dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v1652p6600d0201dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v22B8p3010d0001dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v22B8p4810d0001dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v2735p100Bd*dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v4146pBA01d0100dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:vED06p4500d0001dc*dsc*dp*ic*isc*ip*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc01ip01*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc02ip01*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc03ip01*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc04ip01*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc05ip01*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc06ip01*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc01ip00*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc02ip00*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc03ip00*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc04ip00*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc05ip00*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc06ip00*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc01ip50*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc02ip50*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc03ip50*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc04ip50*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc05ip50*");
MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc06ip50*");

MODULE_INFO(srcversion, "C24BF49B856DBED3EDFB6B9");
