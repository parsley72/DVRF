cmd_arch/mips/lib/csum_partial.o := mipsel-uclibc-linux26-gcc -Wp,-MD,arch/mips/lib/.csum_partial.o.d  -nostdinc -isystem /projects/hnd/tools/linux/hndtools-mipsel-linux-uclibc-4.2.3/lib/gcc/mipsel-linux-uclibc/4.2.3/include -D__KERNEL__ -Iinclude  -include include/linux/autoconf.h -D__ASSEMBLY__ -I../../include  -mabi=32 -G 0 -mno-abicalls -fno-pic -pipe -msoft-float -ggdb -ffreestanding  -march=mips32 -Wa,-mips32 -Wa,--trap  -Iinclude/asm-mips/mach-generic    -c -o arch/mips/lib/csum_partial.o arch/mips/lib/csum_partial.S

deps_arch/mips/lib/csum_partial.o := \
  arch/mips/lib/csum_partial.S \
    $(wildcard include/config/64bit.h) \
    $(wildcard include/config/cpu/little/endian.h) \
    $(wildcard include/config/cpu/sb1.h) \
  include/linux/errno.h \
  include/asm/errno.h \
  include/asm-generic/errno-base.h \
  include/asm/asm.h \
    $(wildcard include/config/printk.h) \
    $(wildcard include/config/cpu/has/prefetch.h) \
  include/asm/sgidefs.h \
  include/asm/asm-offsets.h \
  include/asm/regdef.h \

arch/mips/lib/csum_partial.o: $(deps_arch/mips/lib/csum_partial.o)

$(deps_arch/mips/lib/csum_partial.o):
