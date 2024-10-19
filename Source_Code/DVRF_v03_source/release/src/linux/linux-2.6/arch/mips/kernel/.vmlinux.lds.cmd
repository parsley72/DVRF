cmd_arch/mips/kernel/vmlinux.lds := mipsel-uclibc-linux26-gcc -E -Wp,-MD,arch/mips/kernel/.vmlinux.lds.d  -nostdinc -isystem /projects/hnd/tools/linux/hndtools-mipsel-linux-uclibc-4.2.3/lib/gcc/mipsel-linux-uclibc/4.2.3/include -D__KERNEL__ -Iinclude  -include include/linux/autoconf.h  -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -I../../include -DBCMDRIVER -Dlinux -O2  -mabi=32 -G 0 -mno-abicalls -fno-pic -pipe -msoft-float -ggdb -ffreestanding  -march=mips32 -Wa,-mips32 -Wa,--trap  -Iinclude/asm-mips/mach-generic -D"LOADADDR=0xffffffff80001000" -D"JIFFIES=jiffies_64" -D"DATAOFFSET=0" -P -C -Umips -D__ASSEMBLY__ -o arch/mips/kernel/vmlinux.lds arch/mips/kernel/vmlinux.lds.S

deps_arch/mips/kernel/vmlinux.lds := \
  arch/mips/kernel/vmlinux.lds.S \
    $(wildcard include/config/boot/elf64.h) \
    $(wildcard include/config/mapped/kernel.h) \
    $(wildcard include/config/blk/dev/initrd.h) \
  include/asm/asm-offsets.h \
  include/asm-generic/vmlinux.lds.h \

arch/mips/kernel/vmlinux.lds: $(deps_arch/mips/kernel/vmlinux.lds)

$(deps_arch/mips/kernel/vmlinux.lds):
