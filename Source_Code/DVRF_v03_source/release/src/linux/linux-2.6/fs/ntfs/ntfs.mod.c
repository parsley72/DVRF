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
	{ 0x4d125935, "__kmap_atomic" },
	{ 0xe039ab02, "kmem_cache_destroy" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xec3f606a, "sb_min_blocksize" },
	{ 0x350e2f4, "up_read" },
	{ 0x8ade046c, "__bread" },
	{ 0x559dfe7a, "unload_nls" },
	{ 0x774a1895, "make_bad_inode" },
	{ 0xc3dee7dc, "generic_file_llseek" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x349cba85, "strchr" },
	{ 0x97255bdf, "strlen" },
	{ 0xf70828b, "page_address" },
	{ 0x37c15534, "invalidate_inodes" },
	{ 0x547525a3, "iget5_locked" },
	{ 0xb9116602, "grab_cache_page_nowait" },
	{ 0xc1b4bd87, "malloc_sizes" },
	{ 0x4281717e, "is_bad_inode" },
	{ 0xae744eda, "generic_file_open" },
	{ 0x30a867cb, "__lock_page" },
	{ 0xdcbb9a1, "__lock_buffer" },
	{ 0x20000329, "simple_strtoul" },
	{ 0x158b4c14, "generic_file_aio_read" },
	{ 0xb2643240, "dput" },
	{ 0xaf225792, "seq_printf" },
	{ 0xc4482c92, "dget_locked" },
	{ 0x323222ba, "mutex_unlock" },
	{ 0x85df9b6c, "strsep" },
	{ 0xcb6beb40, "hweight32" },
	{ 0xc5479f3e, "generic_read_dir" },
	{ 0x2fd1d81c, "vfree" },
	{ 0x2574b3f4, "igrab" },
	{ 0x2e08d8b4, "unlock_buffer" },
	{ 0x5ebb56fb, "down_read" },
	{ 0xa13798f8, "printk_ratelimit" },
	{ 0xa4376cb5, "__insert_inode_hash" },
	{ 0x2bc95bd4, "memset" },
	{ 0x6c36a5c1, "__mutex_init" },
	{ 0xdd132261, "printk" },
	{ 0xaca63b34, "d_rehash" },
	{ 0x71c90087, "memcmp" },
	{ 0xf4ee5050, "d_alloc_root" },
	{ 0x38e15260, "d_move" },
	{ 0xa6a8dd49, "kmem_cache_free" },
	{ 0xb97d4c9c, "mutex_lock" },
	{ 0x9f93e780, "__wait_on_buffer" },
	{ 0x948cde9, "num_physpages" },
	{ 0xbc7d49dc, "__kunmap_atomic" },
	{ 0xab61d8bc, "sync_dirty_buffer" },
	{ 0xcd360d1a, "cpu_data" },
	{ 0xcbf2cee7, "__kunmap" },
	{ 0x2f54a823, "unlock_page" },
	{ 0x231cf494, "up_write" },
	{ 0xb3fe02b1, "down_write" },
	{ 0x81a5102c, "__brelse" },
	{ 0xf5651a7f, "inode_init_once" },
	{ 0xde1ebd5e, "kmem_cache_alloc" },
	{ 0x33287679, "generic_file_mmap" },
	{ 0xbe17480d, "generic_file_sendfile" },
	{ 0x7a0189d9, "d_alloc" },
	{ 0xcdacf6b8, "create_empty_buffers" },
	{ 0x12de4243, "load_nls" },
	{ 0x1000e51, "schedule" },
	{ 0x3d9ee9f0, "clear_page" },
	{ 0xdc167c09, "do_sync_read" },
	{ 0x7519bd04, "unlock_new_inode" },
	{ 0x9b7cf49b, "kill_block_super" },
	{ 0x72d113d, "submit_bh" },
	{ 0xfbee9212, "kmem_cache_create" },
	{ 0xafef717, "register_filesystem" },
	{ 0x6989a769, "vsnprintf" },
	{ 0xe6e86f07, "d_lookup" },
	{ 0x4596b861, "iput" },
	{ 0x8e879bb7, "__vmalloc" },
	{ 0x60d1dc17, "read_cache_page" },
	{ 0x37a0cba, "kfree" },
	{ 0x11f7ce5e, "memcpy" },
	{ 0xc94aa405, "load_nls_default" },
	{ 0x59e8c20a, "d_splice_alias" },
	{ 0x5a85e895, "end_buffer_read_sync" },
	{ 0x46462d95, "get_sb_bdev" },
	{ 0x8991be46, "sb_set_blocksize" },
	{ 0xe855c95e, "put_page" },
	{ 0x593aaa4e, "block_sync_page" },
	{ 0xf7fa2ffa, "mark_buffer_dirty" },
	{ 0x8ee003cf, "unregister_filesystem" },
	{ 0x6412dbfe, "__flush_dcache_page" },
	{ 0x576e3e2f, "new_inode" },
	{ 0xaa39f95c, "memmove" },
	{ 0xa33b6313, "__getblk" },
	{ 0xc23a7676, "d_alloc_anon" },
	{ 0x152e0feb, "__kmap" },
	{ 0xc067b911, "d_instantiate" },
	{ 0xc22616f1, "__init_rwsem" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "4751821F65D631352D96445");
