cmd_arch/mips/lib/memcpy.o := mipsel-uclibc-linux26-gcc -Wp,-MD,arch/mips/lib/.memcpy.o.d  -nostdinc -isystem /projects/hnd/tools/linux/hndtools-mipsel-linux-uclibc-4.2.3/lib/gcc/mipsel-linux-uclibc/4.2.3/include -D__KERNEL__ -Iinclude  -include include/linux/autoconf.h -D__ASSEMBLY__ -I../../include  -mabi=32 -G 0 -mno-abicalls -fno-pic -pipe -msoft-float -ggdb -ffreestanding  -march=mips32 -Wa,-mips32 -Wa,--trap  -Iinclude/asm-mips/mach-generic    -c -o arch/mips/lib/memcpy.o arch/mips/lib/memcpy.S

deps_arch/mips/lib/memcpy.o := \
  arch/mips/lib/memcpy.S \
    $(wildcard include/config/dma/coherent.h) \
    $(wildcard include/config/dma/ip27.h) \
    $(wildcard include/config/cpu/has/prefetch.h) \
    $(wildcard include/config/mips/malta.h) \
    $(wildcard include/config/64bit.h) \
    $(wildcard include/config/cpu/little/endian.h) \
    $(wildcard include/config/cpu/sb1.h) \
  include/asm/asm.h \
    $(wildcard include/config/printk.h) \
  include/asm/sgidefs.h \
  include/asm/asm-offsets.h \
  include/asm/regdef.h \

arch/mips/lib/memcpy.o: $(deps_arch/mips/lib/memcpy.o)

$(deps_arch/mips/lib/memcpy.o):
