cmd_drivers/net/ctbootnv/bootnv.o := mipsel-uclibc-linux26-gcc -Wp,-MD,drivers/net/ctbootnv/.bootnv.o.d  -nostdinc -isystem /projects/hnd/tools/linux/hndtools-mipsel-linux-uclibc-4.2.3/lib/gcc/mipsel-linux-uclibc/4.2.3/include -D__KERNEL__ -Iinclude  -include include/linux/autoconf.h -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -I../../include -DBCMDRIVER -Dlinux -O2  -mabi=32 -G 0 -mno-abicalls -fno-pic -pipe -msoft-float -ggdb -ffreestanding  -march=mips32 -Wa,-mips32 -Wa,--trap  -Iinclude/asm-mips/mach-generic -fomit-frame-pointer  -fno-stack-protector -Wdeclaration-after-statement -Wno-pointer-sign -DHNDCTF -DCTFPOOL -DCTFMAP -I/home/dvrf/Download/DVRF_v03/release/src/linux/linux-2.6/../.. -I/home/dvrf/Download/DVRF_v03/release/src/linux/linux-2.6/../../include   -DMODULE -mlong-calls -fno-common -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(bootnv)"  -D"KBUILD_MODNAME=KBUILD_STR(ctbootnv)" -c -o drivers/net/ctbootnv/.tmp_bootnv.o drivers/net/ctbootnv/bootnv.c

deps_drivers/net/ctbootnv/bootnv.o := \
  drivers/net/ctbootnv/bootnv.c \
  include/linux/module.h \
    $(wildcard include/config/modules.h) \
    $(wildcard include/config/modversions.h) \
    $(wildcard include/config/unused/symbols.h) \
    $(wildcard include/config/generic/bug.h) \
    $(wildcard include/config/module/unload.h) \
    $(wildcard include/config/kallsyms.h) \
    $(wildcard include/config/sysfs.h) \
  include/linux/spinlock.h \
    $(wildcard include/config/smp.h) \
    $(wildcard include/config/debug/spinlock.h) \
    $(wildcard include/config/preempt.h) \
    $(wildcard include/config/debug/lock/alloc.h) \
  include/linux/preempt.h \
    $(wildcard include/config/debug/preempt.h) \
  include/linux/thread_info.h \
  include/linux/bitops.h \
  include/asm/types.h \
    $(wildcard include/config/highmem.h) \
    $(wildcard include/config/64bit/phys/addr.h) \
    $(wildcard include/config/64bit.h) \
  include/asm/bitops.h \
    $(wildcard include/config/cpu/mipsr2.h) \
    $(wildcard include/config/cpu/mips32.h) \
    $(wildcard include/config/cpu/mips64.h) \
  include/linux/compiler.h \
    $(wildcard include/config/enable/must/check.h) \
  include/linux/compiler-gcc4.h \
    $(wildcard include/config/forced/inlining.h) \
  include/linux/compiler-gcc.h \
  include/linux/irqflags.h \
    $(wildcard include/config/trace/irqflags.h) \
    $(wildcard include/config/trace/irqflags/support.h) \
    $(wildcard include/config/x86.h) \
  include/asm/irqflags.h \
    $(wildcard include/config/mips/mt/smtc.h) \
    $(wildcard include/config/irq/cpu.h) \
    $(wildcard include/config/mips/mt/smtc/instant/replay.h) \
  include/asm/hazards.h \
    $(wildcard include/config/cpu/r10000.h) \
    $(wildcard include/config/cpu/rm9000.h) \
    $(wildcard include/config/cpu/sb1.h) \
  include/linux/types.h \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/lbd.h) \
    $(wildcard include/config/lsf.h) \
    $(wildcard include/config/resources/64bit.h) \
  include/linux/posix_types.h \
  include/linux/stddef.h \
  include/asm/posix_types.h \
  include/asm/sgidefs.h \
  include/asm/barrier.h \
    $(wildcard include/config/cpu/has/sync.h) \
    $(wildcard include/config/cpu/has/wb.h) \
    $(wildcard include/config/weak/ordering.h) \
  include/asm/bug.h \
    $(wildcard include/config/bug.h) \
  include/asm/break.h \
  include/asm-generic/bug.h \
    $(wildcard include/config/debug/bugverbose.h) \
  include/asm/byteorder.h \
    $(wildcard include/config/cpu/mips64/r2.h) \
  include/linux/byteorder/little_endian.h \
  include/linux/byteorder/swab.h \
  include/linux/byteorder/generic.h \
  include/asm/cpu-features.h \
    $(wildcard include/config/32bit.h) \
    $(wildcard include/config/cpu/mipsr2/irq/vi.h) \
    $(wildcard include/config/cpu/mipsr2/irq/ei.h) \
  include/asm/cpu.h \
  include/asm/cpu-info.h \
    $(wildcard include/config/sgi/ip27.h) \
    $(wildcard include/config/mips/mt.h) \
  include/asm/cache.h \
    $(wildcard include/config/mips/l1/cache/shift.h) \
  include/asm-mips/mach-generic/kmalloc.h \
    $(wildcard include/config/dma/coherent.h) \
  include/asm-mips/mach-generic/cpu-feature-overrides.h \
  include/asm/war.h \
    $(wildcard include/config/sgi/ip22.h) \
    $(wildcard include/config/sni/rm.h) \
    $(wildcard include/config/cpu/r5432.h) \
    $(wildcard include/config/sb1/pass/1/workarounds.h) \
    $(wildcard include/config/sb1/pass/2/workarounds.h) \
    $(wildcard include/config/mips/malta.h) \
    $(wildcard include/config/mips/atlas.h) \
    $(wildcard include/config/mips/sead.h) \
    $(wildcard include/config/cpu/tx49xx.h) \
    $(wildcard include/config/momenco/jaguar/atx.h) \
    $(wildcard include/config/pmc/yosemite.h) \
    $(wildcard include/config/basler/excite.h) \
    $(wildcard include/config/momenco/ocelot.h) \
    $(wildcard include/config/momenco/ocelot/3.h) \
    $(wildcard include/config/momenco/ocelot/c.h) \
    $(wildcard include/config/sgi/ip32.h) \
    $(wildcard include/config/wr/ppmc.h) \
  include/asm-generic/bitops/non-atomic.h \
  include/asm-generic/bitops/fls64.h \
  include/asm-generic/bitops/ffz.h \
  include/asm-generic/bitops/find.h \
  include/asm-generic/bitops/sched.h \
  include/asm-generic/bitops/hweight.h \
  include/asm-generic/bitops/ext2-non-atomic.h \
  include/asm-generic/bitops/le.h \
  include/asm-generic/bitops/ext2-atomic.h \
  include/asm-generic/bitops/minix.h \
  include/asm/thread_info.h \
    $(wildcard include/config/page/size/4kb.h) \
    $(wildcard include/config/bcm/endpointdrv.h) \
    $(wildcard include/config/page/size/8kb.h) \
    $(wildcard include/config/page/size/16kb.h) \
    $(wildcard include/config/page/size/64kb.h) \
    $(wildcard include/config/debug/stack/usage.h) \
  include/asm/processor.h \
    $(wildcard include/config/mips/mt/fpaff.h) \
    $(wildcard include/config/cpu/has/prefetch.h) \
  include/linux/cpumask.h \
    $(wildcard include/config/hotplug/cpu.h) \
  include/linux/kernel.h \
    $(wildcard include/config/preempt/voluntary.h) \
    $(wildcard include/config/debug/spinlock/sleep.h) \
    $(wildcard include/config/printk.h) \
    $(wildcard include/config/numa.h) \
  /projects/hnd/tools/linux/hndtools-mipsel-linux-uclibc-4.2.3/lib/gcc/mipsel-linux-uclibc/4.2.3/include/stdarg.h \
  include/linux/linkage.h \
  include/asm/linkage.h \
  include/linux/log2.h \
    $(wildcard include/config/arch/has/ilog2/u32.h) \
    $(wildcard include/config/arch/has/ilog2/u64.h) \
  include/linux/threads.h \
    $(wildcard include/config/nr/cpus.h) \
    $(wildcard include/config/base/small.h) \
  include/linux/bitmap.h \
  include/linux/string.h \
  include/asm/string.h \
    $(wildcard include/config/cpu/r3000.h) \
  include/asm/cachectl.h \
  include/asm/mipsregs.h \
    $(wildcard include/config/cpu/vr41xx.h) \
  include/asm/prefetch.h \
  include/asm/system.h \
  include/asm/addrspace.h \
    $(wildcard include/config/cpu/r4300.h) \
    $(wildcard include/config/cpu/r4x00.h) \
    $(wildcard include/config/cpu/r5000.h) \
    $(wildcard include/config/cpu/rm7000.h) \
    $(wildcard include/config/cpu/nevada.h) \
    $(wildcard include/config/cpu/r8000.h) \
    $(wildcard include/config/cpu/sb1a.h) \
  include/asm-mips/mach-generic/spaces.h \
    $(wildcard include/config/dma/noncoherent.h) \
  include/asm/dsp.h \
  include/linux/stringify.h \
  include/linux/bottom_half.h \
  include/linux/spinlock_types.h \
  include/linux/lockdep.h \
    $(wildcard include/config/lockdep.h) \
    $(wildcard include/config/generic/hardirqs.h) \
    $(wildcard include/config/prove/locking.h) \
  include/linux/spinlock_types_up.h \
  include/linux/spinlock_up.h \
  include/linux/spinlock_api_up.h \
  include/asm/atomic.h \
  include/asm-generic/atomic.h \
  include/linux/list.h \
    $(wildcard include/config/debug/list.h) \
  include/linux/poison.h \
  include/linux/prefetch.h \
  include/linux/stat.h \
  include/asm/stat.h \
  include/linux/time.h \
  include/linux/seqlock.h \
  include/linux/cache.h \
  include/linux/kmod.h \
    $(wildcard include/config/kmod.h) \
  include/linux/errno.h \
  include/asm/errno.h \
  include/asm-generic/errno-base.h \
  include/linux/elf.h \
  include/linux/auxvec.h \
  include/asm/auxvec.h \
  include/linux/elf-em.h \
  include/asm/elf.h \
    $(wildcard include/config/mips32/n32.h) \
    $(wildcard include/config/mips32/o32.h) \
    $(wildcard include/config/mips32/compat.h) \
  include/linux/kobject.h \
    $(wildcard include/config/hotplug.h) \
  include/linux/sysfs.h \
  include/linux/kref.h \
  include/linux/wait.h \
  include/asm/current.h \
  include/linux/moduleparam.h \
  include/linux/init.h \
    $(wildcard include/config/memory/hotplug.h) \
    $(wildcard include/config/acpi/hotplug/memory.h) \
  include/asm/local.h \
  include/linux/percpu.h \
  include/linux/slab.h \
    $(wildcard include/config/slab/debug.h) \
    $(wildcard include/config/slab.h) \
    $(wildcard include/config/slub.h) \
    $(wildcard include/config/debug/slab.h) \
  include/linux/gfp.h \
    $(wildcard include/config/zone/dma.h) \
    $(wildcard include/config/zone/dma32.h) \
  include/linux/mmzone.h \
    $(wildcard include/config/force/max/zoneorder.h) \
    $(wildcard include/config/arch/populates/node/map.h) \
    $(wildcard include/config/discontigmem.h) \
    $(wildcard include/config/flat/node/mem/map.h) \
    $(wildcard include/config/have/memory/present.h) \
    $(wildcard include/config/need/node/memmap/size.h) \
    $(wildcard include/config/need/multiple/nodes.h) \
    $(wildcard include/config/sparsemem.h) \
    $(wildcard include/config/have/arch/early/pfn/to/nid.h) \
    $(wildcard include/config/flatmem.h) \
    $(wildcard include/config/sparsemem/extreme.h) \
    $(wildcard include/config/nodes/span/other/nodes.h) \
    $(wildcard include/config/holes/in/zone.h) \
  include/linux/numa.h \
    $(wildcard include/config/nodes/shift.h) \
  include/linux/nodemask.h \
  include/asm/page.h \
    $(wildcard include/config/build/elf64.h) \
  include/linux/pfn.h \
  include/asm/io.h \
  include/asm-generic/iomap.h \
  include/asm/pgtable-bits.h \
    $(wildcard include/config/cpu/mips32/r1.h) \
    $(wildcard include/config/cpu/tx39xx.h) \
    $(wildcard include/config/mips/uncached.h) \
  include/asm-mips/mach-generic/ioremap.h \
  include/asm-mips/mach-generic/mangle-port.h \
    $(wildcard include/config/swap/io/space.h) \
  include/asm-generic/memory_model.h \
    $(wildcard include/config/out/of/line/pfn/to/page.h) \
  include/asm-generic/page.h \
  include/linux/memory_hotplug.h \
    $(wildcard include/config/have/arch/nodedata/extension.h) \
  include/linux/notifier.h \
  include/linux/mutex.h \
    $(wildcard include/config/debug/mutexes.h) \
  include/linux/rwsem.h \
    $(wildcard include/config/rwsem/generic/spinlock.h) \
  include/linux/rwsem-spinlock.h \
  include/linux/srcu.h \
  include/linux/topology.h \
    $(wildcard include/config/sched/smt.h) \
    $(wildcard include/config/sched/mc.h) \
  include/linux/smp.h \
  include/asm/topology.h \
  include/asm-mips/mach-generic/topology.h \
  include/asm-generic/topology.h \
  include/asm/sparsemem.h \
  include/linux/slab_def.h \
  include/linux/kmalloc_sizes.h \
  include/asm/percpu.h \
  include/asm-generic/percpu.h \
  include/asm/module.h \
    $(wildcard include/config/cpu/mips32/r2.h) \
    $(wildcard include/config/cpu/mips64/r1.h) \
    $(wildcard include/config/cpu/r6000.h) \
  include/asm/uaccess.h \
  include/asm-generic/uaccess.h \
  include/linux/config.h \
    $(wildcard include/config/h.h) \
    $(wildcard include/config/ipv6.h) \
    $(wildcard include/config/pppoe.h) \
    $(wildcard include/config/net/cls/tcindex.h) \
  include/linux/../../../../cy_conf.h \
    $(wildcard include/config/dnsmasq.h) \
    $(wildcard include/config/dnsmasq//.h) \
    $(wildcard include/config/udhcpd.h) \
    $(wildcard include/config/udhcpd//.h) \
    $(wildcard include/config/udhcpc.h) \
    $(wildcard include/config/udhcpc//.h) \
    $(wildcard include/config/pppoe//.h) \
    $(wildcard include/config/pptp.h) \
    $(wildcard include/config/pptp//.h) \
    $(wildcard include/config/pptp/dhcpc.h) \
    $(wildcard include/config/pptp/dhcpc//.h) \
    $(wildcard include/config/l2tp.h) \
    $(wildcard include/config/l2tp//.h) \
    $(wildcard include/config/pppd.h) \
    $(wildcard include/config/pppd//.h) \
    $(wildcard include/config/routed.h) \
    $(wildcard include/config/routed//.h) \
    $(wildcard include/config/zebra.h) \
    $(wildcard include/config/zebra//.h) \
    $(wildcard include/config/tftpd.h) \
    $(wildcard include/config/tftpd//.h) \
    $(wildcard include/config/ddns.h) \
    $(wildcard include/config/ddns//.h) \
    $(wildcard include/config/tzo/web/client2.h) \
    $(wildcard include/config/tzo/web/client2//.h) \
    $(wildcard include/config/cron.h) \
    $(wildcard include/config/cron//.h) \
    $(wildcard include/config/httpd.h) \
    $(wildcard include/config/httpd//.h) \
    $(wildcard include/config/get/post.h) \
    $(wildcard include/config/get/post//.h) \
    $(wildcard include/config/custom404.h) \
    $(wildcard include/config/custom404//.h) \
    $(wildcard include/config/trendmicro/sss.h) \
    $(wildcard include/config/trendmicro/sss//.h) \
    $(wildcard include/config/hnap.h) \
    $(wildcard include/config/hnap//.h) \
    $(wildcard include/config/hnap/ssdpdiscovery.h) \
    $(wildcard include/config/hnap/ssdpdiscovery//.h) \
    $(wildcard include/config/hnap/spec/v11.h) \
    $(wildcard include/config/hnap/spec/v11//.h) \
    $(wildcard include/config/hnap/spec/v12.h) \
    $(wildcard include/config/hnap/spec/v12//.h) \
    $(wildcard include/config/hnap/dhcp/reservations.h) \
    $(wildcard include/config/hnap/dhcp/reservations//.h) \
    $(wildcard include/config/expat.h) \
    $(wildcard include/config/expat//.h) \
    $(wildcard include/config/heartbeat.h) \
    $(wildcard include/config/heartbeat//.h) \
    $(wildcard include/config/https.h) \
    $(wildcard include/config/https//.h) \
    $(wildcard include/config/multicast.h) \
    $(wildcard include/config/multicast//.h) \
    $(wildcard include/config/igmp/x/mld.h) \
    $(wildcard include/config/igmp/x/mld//.h) \
    $(wildcard include/config/igmpv3.h) \
    $(wildcard include/config/igmpv3//.h) \
    $(wildcard include/config/igmp/hosttrack.h) \
    $(wildcard include/config/igmp/hosttrack//.h) \
    $(wildcard include/config/setup/wizard.h) \
    $(wildcard include/config/setup/wizard//.h) \
    $(wildcard include/config/push/button/test.h) \
    $(wildcard include/config/push/button/test//.h) \
    $(wildcard include/config/single/forward.h) \
    $(wildcard include/config/single/forward//.h) \
    $(wildcard include/config/udhcpd/static.h) \
    $(wildcard include/config/udhcpd/static//.h) \
    $(wildcard include/config/xbox.h) \
    $(wildcard include/config/xbox//.h) \
    $(wildcard include/config/backup/restore.h) \
    $(wildcard include/config/backup/restore//.h) \
    $(wildcard include/config/port/trigger.h) \
    $(wildcard include/config/port/trigger//.h) \
    $(wildcard include/config/hw/qos.h) \
    $(wildcard include/config/hw/qos//.h) \
    $(wildcard include/config/sw/qos.h) \
    $(wildcard include/config/sw/qos//.h) \
    $(wildcard include/config/write/mac.h) \
    $(wildcard include/config/write/mac//.h) \
    $(wildcard include/config/write/sn.h) \
    $(wildcard include/config/write/sn//.h) \
    $(wildcard include/config/write/country.h) \
    $(wildcard include/config/write/country//.h) \
    $(wildcard include/config/write/pa.h) \
    $(wildcard include/config/write/pa//.h) \
    $(wildcard include/config/bootnv.h) \
    $(wildcard include/config/bootnv//.h) \
    $(wildcard include/config/mfgtest.h) \
    $(wildcard include/config/mfgtest//.h) \
    $(wildcard include/config/diag.h) \
    $(wildcard include/config/diag//.h) \
    $(wildcard include/config/boot/dhcpd.h) \
    $(wildcard include/config/boot/dhcpd//.h) \
    $(wildcard include/config/boot/httpd.h) \
    $(wildcard include/config/boot/httpd//.h) \
    $(wildcard include/config/wireless.h) \
    $(wildcard include/config/wireless//.h) \
    $(wildcard include/config/eou.h) \
    $(wildcard include/config/eou//.h) \
    $(wildcard include/config/wcn.h) \
    $(wildcard include/config/wcn//.h) \
    $(wildcard include/config/wcn2.h) \
    $(wildcard include/config/wcn2//.h) \
    $(wildcard include/config/wsc.h) \
    $(wildcard include/config/wsc//.h) \
    $(wildcard include/config/write/wsc/pin.h) \
    $(wildcard include/config/write/wsc/pin//.h) \
    $(wildcard include/config/wsc/c.h) \
    $(wildcard include/config/wsc/c//.h) \
    $(wildcard include/config/wsc/cplus.h) \
    $(wildcard include/config/wsc/cplus//.h) \
    $(wildcard include/config/xyssl.h) \
    $(wildcard include/config/xyssl//.h) \
    $(wildcard include/config/polarssl.h) \
    $(wildcard include/config/polarssl//.h) \
    $(wildcard include/config/ezc.h) \
    $(wildcard include/config/ezc//.h) \
    $(wildcard include/config/ses.h) \
    $(wildcard include/config/ses//.h) \
    $(wildcard include/config/ses/button.h) \
    $(wildcard include/config/ses/button//.h) \
    $(wildcard include/config/aoss.h) \
    $(wildcard include/config/aoss//.h) \
    $(wildcard include/config/speed/booster.h) \
    $(wildcard include/config/speed/booster//.h) \
    $(wildcard include/config/disable/11n/40m.h) \
    $(wildcard include/config/disable/11n/40m//.h) \
    $(wildcard include/config/wireless/5g/band.h) \
    $(wildcard include/config/wireless/5g/band//.h) \
    $(wildcard include/config/sele/dual/band.h) \
    $(wildcard include/config/sele/dual/band//.h) \
    $(wildcard include/config/simul/dual/band.h) \
    $(wildcard include/config/simul/dual/band//.h) \
    $(wildcard include/config/monitor/usb.h) \
    $(wildcard include/config/monitor/usb//.h) \
    $(wildcard include/config/multiple/login.h) \
    $(wildcard include/config/multiple/login//.h) \
    $(wildcard include/config/tinylogin.h) \
    $(wildcard include/config/tinylogin//.h) \
    $(wildcard include/config/busybox/login.h) \
    $(wildcard include/config/busybox/login//.h) \
    $(wildcard include/config/paragon/ntfs.h) \
    $(wildcard include/config/paragon/ntfs//.h) \
    $(wildcard include/config/storage.h) \
    $(wildcard include/config/storage//.h) \
    $(wildcard include/config/smb302.h) \
    $(wildcard include/config/smb302//.h) \
    $(wildcard include/config/smb3025.h) \
    $(wildcard include/config/smb3025//.h) \
    $(wildcard include/config/smb3215.h) \
    $(wildcard include/config/smb3215//.h) \
    $(wildcard include/config/nmbd/name/register.h) \
    $(wildcard include/config/nmbd/name/register//.h) \
    $(wildcard include/config/ftp.h) \
    $(wildcard include/config/ftp//.h) \
    $(wildcard include/config/vsftpd.h) \
    $(wildcard include/config/vsftpd//.h) \
    $(wildcard include/config/proftpd.h) \
    $(wildcard include/config/proftpd//.h) \
    $(wildcard include/config/media/server.h) \
    $(wildcard include/config/media/server//.h) \
    $(wildcard include/config/email/alert.h) \
    $(wildcard include/config/email/alert//.h) \
    $(wildcard include/config/printer/server.h) \
    $(wildcard include/config/printer/server//.h) \
    $(wildcard include/config/tcp/wrapper.h) \
    $(wildcard include/config/tcp/wrapper//.h) \
    $(wildcard include/config/popt.h) \
    $(wildcard include/config/popt//.h) \
    $(wildcard include/config/raid.h) \
    $(wildcard include/config/raid//.h) \
    $(wildcard include/config/gmp.h) \
    $(wildcard include/config/gmp//.h) \
    $(wildcard include/config/mkdosfs.h) \
    $(wildcard include/config/mkdosfs//.h) \
    $(wildcard include/config/dosfstools.h) \
    $(wildcard include/config/dosfstools//.h) \
    $(wildcard include/config/respart.h) \
    $(wildcard include/config/respart//.h) \
    $(wildcard include/config/archive.h) \
    $(wildcard include/config/archive//.h) \
    $(wildcard include/config/disconnect/disk.h) \
    $(wildcard include/config/disconnect/disk//.h) \
    $(wildcard include/config/user/group.h) \
    $(wildcard include/config/user/group//.h) \
    $(wildcard include/config/user/note.h) \
    $(wildcard include/config/user/note//.h) \
    $(wildcard include/config/wipedisks.h) \
    $(wildcard include/config/wipedisks//.h) \
    $(wildcard include/config/disktestwait.h) \
    $(wildcard include/config/disktestwait//.h) \
    $(wildcard include/config/secsrl.h) \
    $(wildcard include/config/secsrl//.h) \
    $(wildcard include/config/seutil.h) \
    $(wildcard include/config/seutil//.h) \
    $(wildcard include/config/nfs.h) \
    $(wildcard include/config/nfs//.h) \
    $(wildcard include/config/portmap.h) \
    $(wildcard include/config/portmap//.h) \
    $(wildcard include/config/mpppoe.h) \
    $(wildcard include/config/mpppoe//.h) \
    $(wildcard include/config/unnumberip.h) \
    $(wildcard include/config/unnumberip//.h) \
    $(wildcard include/config/ddns3322.h) \
    $(wildcard include/config/ddns3322//.h) \
    $(wildcard include/config/peanuthull.h) \
    $(wildcard include/config/peanuthull//.h) \
    $(wildcard include/config/multilang.h) \
    $(wildcard include/config/multilang//.h) \
    $(wildcard include/config/multilang/page.h) \
    $(wildcard include/config/multilang/page//.h) \
    $(wildcard include/config/multilang/gui.h) \
    $(wildcard include/config/multilang/gui//.h) \
    $(wildcard include/config/vlan.h) \
    $(wildcard include/config/vlan//.h) \
    $(wildcard include/config/parental/control.h) \
    $(wildcard include/config/parental/control//.h) \
    $(wildcard include/config/snmp.h) \
    $(wildcard include/config/snmp//.h) \
    $(wildcard include/config/hsiab.h) \
    $(wildcard include/config/hsiab//.h) \
    $(wildcard include/config/ddm.h) \
    $(wildcard include/config/ddm//.h) \
    $(wildcard include/config/utelnetd.h) \
    $(wildcard include/config/utelnetd//.h) \
    $(wildcard include/config/symc/outbreak.h) \
    $(wildcard include/config/symc/outbreak//.h) \
    $(wildcard include/config/ebtables.h) \
    $(wildcard include/config/ebtables//.h) \
    $(wildcard include/config/lltd.h) \
    $(wildcard include/config/lltd//.h) \
    $(wildcard include/config/http/simple.h) \
    $(wildcard include/config/http/simple//.h) \
    $(wildcard include/config/pciutils.h) \
    $(wildcard include/config/pciutils//.h) \
    $(wildcard include/config/wl/iocmd.h) \
    $(wildcard include/config/wl/iocmd//.h) \
    $(wildcard include/config/wl/full.h) \
    $(wildcard include/config/wl/full//.h) \
    $(wildcard include/config/syslog.h) \
    $(wildcard include/config/syslog//.h) \
    $(wildcard include/config/klogd.h) \
    $(wildcard include/config/klogd//.h) \
    $(wildcard include/config/wl/wds.h) \
    $(wildcard include/config/wl/wds//.h) \
    $(wildcard include/config/wl/sta.h) \
    $(wildcard include/config/wl/sta//.h) \
    $(wildcard include/config/wake/on/lan.h) \
    $(wildcard include/config/wake/on/lan//.h) \
    $(wildcard include/config/samba.h) \
    $(wildcard include/config/samba//.h) \
    $(wildcard include/config/upnp/forward.h) \
    $(wildcard include/config/upnp/forward//.h) \
    $(wildcard include/config/performance.h) \
    $(wildcard include/config/performance//.h) \
    $(wildcard include/config/pppoe/server.h) \
    $(wildcard include/config/pppoe/server//.h) \
    $(wildcard include/config/aol.h) \
    $(wildcard include/config/aol//.h) \
    $(wildcard include/config/emi/test.h) \
    $(wildcard include/config/emi/test//.h) \
    $(wildcard include/config/throughput/test.h) \
    $(wildcard include/config/throughput/test//.h) \
    $(wildcard include/config/for/tmobile/test.h) \
    $(wildcard include/config/for/tmobile/test//.h) \
    $(wildcard include/config/curl.h) \
    $(wildcard include/config/curl//.h) \
    $(wildcard include/config/t/mobile.h) \
    $(wildcard include/config/t/mobile//.h) \
    $(wildcard include/config/rxp.h) \
    $(wildcard include/config/rxp//.h) \
    $(wildcard include/config/t/cert.h) \
    $(wildcard include/config/t/cert//.h) \
    $(wildcard include/config/cell/vendor/test.h) \
    $(wildcard include/config/cell/vendor/test//.h) \
    $(wildcard include/config/dual/image.h) \
    $(wildcard include/config/dual/image//.h) \
    $(wildcard include/config/igmp/snoop.h) \
    $(wildcard include/config/igmp/snoop//.h) \
    $(wildcard include/config/emf.h) \
    $(wildcard include/config/emf//.h) \
    $(wildcard include/config/ipv6//.h) \
    $(wildcard include/config/radvd.h) \
    $(wildcard include/config/radvd//.h) \
    $(wildcard include/config/iproute2.h) \
    $(wildcard include/config/iproute2//.h) \
    $(wildcard include/config/iputils.h) \
    $(wildcard include/config/iputils//.h) \
    $(wildcard include/config/dhcpv6s.h) \
    $(wildcard include/config/dhcpv6s//.h) \
    $(wildcard include/config/dhcpv6c.h) \
    $(wildcard include/config/dhcpv6c//.h) \
    $(wildcard include/config/twonky.h) \
    $(wildcard include/config/twonky//.h) \
    $(wildcard include/config/boot128k.h) \
    $(wildcard include/config/boot128k//.h) \
    $(wildcard include/config/eghn.h) \
    $(wildcard include/config/eghn//.h) \
    $(wildcard include/config/three/arp/gratuatous.h) \
    $(wildcard include/config/three/arp/gratuatous//.h) \
    $(wildcard include/config/selfsign.h) \
    $(wildcard include/config/selfsign//.h) \
    $(wildcard include/config/build/mfg.h) \
    $(wildcard include/config/build/mfg//.h) \
    $(wildcard include/config/wl/app.h) \
    $(wildcard include/config/wl/app//.h) \
    $(wildcard include/config/gui/timeout.h) \
    $(wildcard include/config/gui/timeout//.h) \
    $(wildcard include/config/ipv6/security.h) \
    $(wildcard include/config/ipv6/security//.h) \
    $(wildcard include/config/alg.h) \
    $(wildcard include/config/alg/module//.h) \
    $(wildcard include/config/auto/detect/language.h) \
    $(wildcard include/config/auto/detect/language//.h) \
    $(wildcard include/config/wireless/warning/page.h) \
    $(wildcard include/config/wireless/warning/page//.h) \
    $(wildcard include/config/guest/network.h) \
    $(wildcard include/config/guest/network//.h) \
    $(wildcard include/config/hotspot.h) \
    $(wildcard include/config/hotspot//.h) \
    $(wildcard include/config/wan/detect.h) \
    $(wildcard include/config/wan/detect//.h) \
    $(wildcard include/config/ces/parental/control.h) \
    $(wildcard include/config/ces/parental/control//.h) \
    $(wildcard include/config/ces/mdns.h) \
    $(wildcard include/config/ces/mdns//.h) \
    $(wildcard include/config/ces/e/series.h) \
    $(wildcard include/config/ces/e/series//.h) \
    $(wildcard include/config/router2switch.h) \
    $(wildcard include/config/router2switch//.h) \
    $(wildcard include/config/usbap.h) \
    $(wildcard include/config/usbap//.h) \
    $(wildcard include/config/virtual/usb.h) \
    $(wildcard include/config/virtual/usb//.h) \
  include/linux/proc_fs.h \
    $(wildcard include/config/proc/fs.h) \
    $(wildcard include/config/proc/devicetree.h) \
    $(wildcard include/config/proc/kcore.h) \
    $(wildcard include/config/mmu.h) \
  include/linux/fs.h \
    $(wildcard include/config/dnotify.h) \
    $(wildcard include/config/quota.h) \
    $(wildcard include/config/inotify.h) \
    $(wildcard include/config/security.h) \
    $(wildcard include/config/epoll.h) \
    $(wildcard include/config/auditsyscall.h) \
    $(wildcard include/config/block.h) \
    $(wildcard include/config/fs/xip.h) \
    $(wildcard include/config/migration.h) \
  include/linux/limits.h \
  include/linux/ioctl.h \
  include/asm/ioctl.h \
  include/linux/kdev_t.h \
  include/linux/dcache.h \
    $(wildcard include/config/profiling.h) \
  include/linux/rcupdate.h \
  include/linux/namei.h \
  include/linux/radix-tree.h \
  include/linux/prio_tree.h \
  include/linux/pid.h \
  include/asm/semaphore.h \
  include/linux/quota.h \
  include/linux/dqblk_xfs.h \
  include/linux/dqblk_v1.h \
  include/linux/dqblk_v2.h \
  include/linux/nfs_fs_i.h \
  include/linux/nfs.h \
  include/linux/sunrpc/msg_prot.h \
  include/linux/fcntl.h \
  include/asm/fcntl.h \
  include/asm-generic/fcntl.h \
  include/linux/err.h \
  include/linux/magic.h \
  ../../include/bcmutils.h \
  ../../include/osl.h \
  ../../include/linux_osl.h \
    $(wildcard include/config/mmc/msm7x00a.h) \
  ../../include/typedefs.h \
  include/linux/version.h \
  ../../include/bcmdefs.h \
  ../../include/linuxver.h \
    $(wildcard include/config/net/radio.h) \
    $(wildcard include/config/wireless/ext.h) \
    $(wildcard include/config/pcmcia.h) \
    $(wildcard include/config/rfkill/input.h) \
  include/linux/mm.h \
    $(wildcard include/config/sysctl.h) \
    $(wildcard include/config/stack/growsup.h) \
    $(wildcard include/config/debug/vm.h) \
    $(wildcard include/config/shmem.h) \
    $(wildcard include/config/split/ptlock/cpus.h) \
    $(wildcard include/config/ia64.h) \
    $(wildcard include/config/debug/pagealloc.h) \
  include/linux/capability.h \
  include/linux/rbtree.h \
  include/linux/debug_locks.h \
    $(wildcard include/config/debug/locking/api/selftests.h) \
  include/linux/backing-dev.h \
  include/linux/mm_types.h \
  include/asm/pgtable.h \
  include/asm/pgtable-32.h \
  include/asm/fixmap.h \
    $(wildcard include/config/bcm47xx.h) \
  include/asm/kmap_types.h \
    $(wildcard include/config/debug/highmem.h) \
  include/asm-generic/pgtable-nopmd.h \
  include/asm-generic/pgtable-nopud.h \
  include/asm-generic/pgtable.h \
  include/linux/page-flags.h \
    $(wildcard include/config/s390.h) \
    $(wildcard include/config/swap.h) \
  include/linux/vmstat.h \
    $(wildcard include/config/vm/event/counters.h) \
  include/linux/pci.h \
    $(wildcard include/config/pci/msi.h) \
    $(wildcard include/config/pci.h) \
    $(wildcard include/config/ht/irq.h) \
    $(wildcard include/config/pci/domains.h) \
  include/linux/pci_regs.h \
  include/linux/mod_devicetable.h \
  include/linux/ioport.h \
  include/linux/device.h \
    $(wildcard include/config/debug/devres.h) \
  include/linux/klist.h \
  include/linux/completion.h \
  include/linux/pm.h \
    $(wildcard include/config/pm.h) \
  include/asm/device.h \
  include/asm-generic/device.h \
  include/linux/pci_ids.h \
  include/linux/dmapool.h \
  include/asm/scatterlist.h \
  include/asm/pci.h \
    $(wildcard include/config/dma/need/pci/map/state.h) \
  include/asm-generic/pci-dma-compat.h \
  include/linux/dma-mapping.h \
  include/asm/dma-mapping.h \
  include/linux/interrupt.h \
    $(wildcard include/config/high/res/timers.h) \
    $(wildcard include/config/generic/irq/probe.h) \
  include/linux/irqreturn.h \
  include/linux/hardirq.h \
    $(wildcard include/config/preempt/bkl.h) \
    $(wildcard include/config/virt/cpu/accounting.h) \
  include/linux/smp_lock.h \
    $(wildcard include/config/lock/kernel.h) \
  include/asm/hardirq.h \
  include/linux/irq.h \
    $(wildcard include/config/irq/per/cpu.h) \
    $(wildcard include/config/irq/release/method.h) \
    $(wildcard include/config/generic/pending/irq.h) \
    $(wildcard include/config/irqbalance.h) \
    $(wildcard include/config/auto/irq/affinity.h) \
    $(wildcard include/config/generic/hardirqs/no//do/irq.h) \
  include/asm/irq.h \
    $(wildcard include/config/i8259.h) \
  include/asm/mipsmtregs.h \
  include/asm-mips/mach-generic/irq.h \
    $(wildcard include/config/irq/cpu/rm7k.h) \
    $(wildcard include/config/irq/cpu/rm9k.h) \
  include/asm/ptrace.h \
    $(wildcard include/config/cpu/has/smartmips.h) \
  include/asm/isadep.h \
  include/asm/irq_regs.h \
  include/asm/hw_irq.h \
  include/linux/profile.h \
  include/linux/irq_cpustat.h \
  include/linux/sched.h \
    $(wildcard include/config/no/hz.h) \
    $(wildcard include/config/detect/softlockup.h) \
    $(wildcard include/config/keys.h) \
    $(wildcard include/config/bsd/process/acct.h) \
    $(wildcard include/config/taskstats.h) \
    $(wildcard include/config/inotify/user.h) \
    $(wildcard include/config/schedstats.h) \
    $(wildcard include/config/task/delay/acct.h) \
    $(wildcard include/config/blk/dev/io/trace.h) \
    $(wildcard include/config/cc/stackprotector.h) \
    $(wildcard include/config/sysvipc.h) \
    $(wildcard include/config/rt/mutexes.h) \
    $(wildcard include/config/task/xacct.h) \
    $(wildcard include/config/cpusets.h) \
    $(wildcard include/config/compat.h) \
    $(wildcard include/config/fault/injection.h) \
  include/asm/param.h \
    $(wildcard include/config/hz.h) \
  include/linux/timex.h \
    $(wildcard include/config/time/interpolation.h) \
  include/asm/timex.h \
  include/asm-mips/mach-generic/timex.h \
  include/linux/jiffies.h \
  include/linux/calc64.h \
  include/asm/div64.h \
  include/asm/compiler.h \
  include/asm/mmu.h \
  include/asm/cputime.h \
  include/asm-generic/cputime.h \
  include/linux/sem.h \
  include/linux/ipc.h \
    $(wildcard include/config/ipc/ns.h) \
  include/asm/ipcbuf.h \
  include/asm/sembuf.h \
  include/linux/signal.h \
  include/asm/signal.h \
    $(wildcard include/config/trad/signals.h) \
    $(wildcard include/config/binfmt/irix.h) \
  include/asm-generic/signal.h \
  include/asm/sigcontext.h \
  include/asm/siginfo.h \
  include/asm-generic/siginfo.h \
  include/linux/securebits.h \
  include/linux/fs_struct.h \
  include/linux/seccomp.h \
    $(wildcard include/config/seccomp.h) \
  include/linux/futex.h \
    $(wildcard include/config/futex.h) \
  include/linux/rtmutex.h \
    $(wildcard include/config/debug/rt/mutexes.h) \
  include/linux/plist.h \
    $(wildcard include/config/debug/pi/list.h) \
  include/linux/param.h \
  include/linux/resource.h \
  include/asm/resource.h \
  include/asm-generic/resource.h \
  include/linux/timer.h \
    $(wildcard include/config/timer/stats.h) \
  include/linux/ktime.h \
    $(wildcard include/config/ktime/scalar.h) \
  include/linux/hrtimer.h \
  include/linux/task_io_accounting.h \
    $(wildcard include/config/task/io/accounting.h) \
  include/linux/aio.h \
  include/linux/workqueue.h \
  include/linux/aio_abi.h \
  include/linux/uio.h \
  include/linux/netdevice.h \
    $(wildcard include/config/inet/gro.h) \
    $(wildcard include/config/ax25.h) \
    $(wildcard include/config/tr.h) \
    $(wildcard include/config/net/ipip.h) \
    $(wildcard include/config/net/ipgre.h) \
    $(wildcard include/config/ipv6/sit.h) \
    $(wildcard include/config/ipv6/tunnel.h) \
    $(wildcard include/config/netpoll.h) \
    $(wildcard include/config/net/poll/controller.h) \
    $(wildcard include/config/netpoll/trap.h) \
    $(wildcard include/config/net/dma.h) \
  include/linux/if.h \
  include/linux/socket.h \
  include/asm/socket.h \
  include/asm/sockios.h \
  include/linux/sockios.h \
  include/linux/hdlc/ioctl.h \
  include/linux/if_ether.h \
  include/linux/skbuff.h \
    $(wildcard include/config/nf/conntrack.h) \
    $(wildcard include/config/bridge/netfilter.h) \
    $(wildcard include/config/vlan/8021q.h) \
    $(wildcard include/config/netfilter/xt/match/layer7.h) \
    $(wildcard include/config/net/sched.h) \
    $(wildcard include/config/net/cls/act.h) \
    $(wildcard include/config/network/secmark.h) \
  include/linux/net.h \
  include/linux/random.h \
  include/linux/sysctl.h \
    $(wildcard include/config/bcm/nat.h) \
  include/linux/textsearch.h \
  include/net/checksum.h \
  include/asm/checksum.h \
  include/linux/in6.h \
  include/linux/dmaengine.h \
    $(wildcard include/config/dma/engine.h) \
  include/linux/if_packet.h \
  include/net/ieee80211.h \
    $(wildcard include/config/ieee80211/debug.h) \
  include/linux/wireless.h \
  include/linux/if_arp.h \
  include/net/iw_handler.h \
  include/net/ieee80211_crypt.h \
  include/asm/paccess.h \
  ../../include/ctf/hndctf.h \
  ../../include/proto/bcmip.h \
  ../../include/packed_section_start.h \
  ../../include/packed_section_end.h \
  ../../include/proto/ethernet.h \
  ../../include/siutils.h \
  ../../include/bcmnvram.h \
  ../../include/code_pattern.h \
  ../../include/flash.h \
  ../../include/flashutl.h \
  ../../include/sflash.h \
  ../../include/sbchipc.h \
    $(wildcard include/config/legacy3wire.h) \
  ../../include/bootnv.h \
  ../../include/cy_conf.h \
  ../../include/flash_layout.h \

drivers/net/ctbootnv/bootnv.o: $(deps_drivers/net/ctbootnv/bootnv.o)

$(deps_drivers/net/ctbootnv/bootnv.o):
