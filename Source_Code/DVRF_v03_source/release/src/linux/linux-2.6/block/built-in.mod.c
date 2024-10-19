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
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xf9a482f9, "msleep" },
	{ 0x70c1226b, "bio_copy_user" },
	{ 0x75b38522, "del_timer" },
	{ 0xf70828b, "page_address" },
	{ 0x5b2c3a32, "bd_release" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0xc1b4bd87, "malloc_sizes" },
	{ 0x50920531, "blk_queue_bounce" },
	{ 0xf7af0c84, "seq_puts" },
	{ 0x70930619, "bio_unmap_user" },
	{ 0xc633495b, "schedule_work" },
	{ 0xaf225792, "seq_printf" },
	{ 0xa08901eb, "cancel_work_sync" },
	{ 0xac54fc9f, "mempool_destroy" },
	{ 0xfbea45e6, "queue_work" },
	{ 0xadb792c2, "prepare_to_wait_exclusive" },
	{ 0x323222ba, "mutex_unlock" },
	{ 0x6876581b, "raise_softirq_irqoff" },
	{ 0x7d11c268, "jiffies" },
	{ 0x52354a0b, "mutex_trylock" },
	{ 0x1dfa97dd, "fsync_bdev" },
	{ 0xd41dff64, "invalidate_bdev" },
	{ 0x12f237eb, "__kzalloc" },
	{ 0xbeb32c43, "__create_workqueue" },
	{ 0xb6091ec0, "__copy_user" },
	{ 0x183fa88b, "mempool_alloc_slab" },
	{ 0x25fa6f17, "wait_for_completion" },
	{ 0x8a514eb2, "__invalidate_device" },
	{ 0x2bc95bd4, "memset" },
	{ 0x6953566f, "bio_map_user" },
	{ 0x37befc70, "jiffies_to_msecs" },
	{ 0x6c36a5c1, "__mutex_init" },
	{ 0x6d294e43, "clock_t_to_jiffies" },
	{ 0xdd132261, "printk" },
	{ 0x1075bf0, "panic" },
	{ 0x76d3cd60, "laptop_mode" },
	{ 0xa6a8dd49, "kmem_cache_free" },
	{ 0x93a6e0b2, "io_schedule" },
	{ 0xb97d4c9c, "mutex_lock" },
	{ 0x4164a9cd, "mem_section" },
	{ 0x20187c7, "mod_timer" },
	{ 0xcd360d1a, "cpu_data" },
	{ 0x37d4196b, "clear_bdi_congested" },
	{ 0x8a99a016, "mempool_free_slab" },
	{ 0xf825cc25, "bio_endio" },
	{ 0x38b3bcb4, "bio_put" },
	{ 0x83a1f4fd, "module_put" },
	{ 0x7dceceac, "capable" },
	{ 0xdcdc604b, "init_task" },
	{ 0xde1ebd5e, "kmem_cache_alloc" },
	{ 0xab53b0a8, "mempool_alloc" },
	{ 0xd3427f73, "mempool_create_node" },
	{ 0x549c4c, "bdevname" },
	{ 0xbc15ef72, "bio_map_kern" },
	{ 0x8e51fca6, "bio_hw_segments" },
	{ 0x5b4eccc5, "put_device" },
	{ 0x3bd1b1f6, "msecs_to_jiffies" },
	{ 0x6b2dc060, "dump_stack" },
	{ 0xb30a88b1, "sysfs_create_file" },
	{ 0x62aba95, "mempool_free" },
	{ 0x1d45ad21, "get_device" },
	{ 0xfbee9212, "kmem_cache_create" },
	{ 0x6cb34e5, "init_waitqueue_head" },
	{ 0x35fe47a1, "init_timer" },
	{ 0xb6c70a7d, "__wake_up" },
	{ 0x8e488408, "bio_uncopy_user" },
	{ 0x37a0cba, "kfree" },
	{ 0x11f7ce5e, "memcpy" },
	{ 0x98adfde2, "request_module" },
	{ 0xaf2cda9a, "bio_phys_segments" },
	{ 0x51493d94, "finish_wait" },
	{ 0xa218bf61, "complete" },
	{ 0x8191bd0, "bdget" },
	{ 0x79e68528, "set_blocksize" },
	{ 0xc77b7fdb, "add_disk_randomness" },
	{ 0x4ce41dda, "bd_claim" },
	{ 0x9b0125c2, "bdput" },
	{ 0x4d03329, "set_bdi_congested" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=built-in,built-in,built-in,built-in,init_task,built-in";

