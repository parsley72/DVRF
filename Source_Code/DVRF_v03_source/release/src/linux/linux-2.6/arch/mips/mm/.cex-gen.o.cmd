cmd_arch/mips/mm/cex-gen.o := mipsel-uclibc-linux26-gcc -Wp,-MD,arch/mips/mm/.cex-gen.o.d  -nostdinc -isystem /projects/hnd/tools/linux/hndtools-mipsel-linux-uclibc-4.2.3/lib/gcc/mipsel-linux-uclibc/4.2.3/include -D__KERNEL__ -Iinclude  -include include/linux/autoconf.h -D__ASSEMBLY__ -I../../include  -mabi=32 -G 0 -mno-abicalls -fno-pic -pipe -msoft-float -ggdb -ffreestanding  -march=mips32 -Wa,-mips32 -Wa,--trap  -Iinclude/asm-mips/mach-generic    -c -o arch/mips/mm/cex-gen.o arch/mips/mm/cex-gen.S

deps_arch/mips/mm/cex-gen.o := \
  arch/mips/mm/cex-gen.S \
  include/asm/asm.h \
    $(wildcard include/config/printk.h) \
    $(wildcard include/config/cpu/has/prefetch.h) \
  include/asm/sgidefs.h \
  include/asm/regdef.h \
  include/asm/mipsregs.h \
    $(wildcard include/config/cpu/vr41xx.h) \
    $(wildcard include/config/page/size/4kb.h) \
    $(wildcard include/config/page/size/16kb.h) \
    $(wildcard include/config/page/size/64kb.h) \
    $(wildcard include/config/mips/mt/smtc.h) \
  include/linux/linkage.h \
  include/asm/linkage.h \
  include/asm/hazards.h \
    $(wildcard include/config/cpu/mipsr2.h) \
    $(wildcard include/config/cpu/r10000.h) \
    $(wildcard include/config/cpu/rm9000.h) \
    $(wildcard include/config/cpu/sb1.h) \
  include/asm/stackframe.h \
    $(wildcard include/config/cpu/r3000.h) \
    $(wildcard include/config/cpu/tx39xx.h) \
    $(wildcard include/config/cpu/has/smartmips.h) \
    $(wildcard include/config/32bit.h) \
    $(wildcard include/config/smp.h) \
    $(wildcard include/config/build/elf64.h) \
    $(wildcard include/config/64bit.h) \
    $(wildcard include/config/bcm47xx.h) \
  include/linux/threads.h \
    $(wildcard include/config/nr/cpus.h) \
    $(wildcard include/config/base/small.h) \
  include/asm/asmmacro.h \
  include/asm/asmmacro-32.h \
  include/asm/asm-offsets.h \
  include/asm/fpregdef.h \

arch/mips/mm/cex-gen.o: $(deps_arch/mips/mm/cex-gen.o)

$(deps_arch/mips/mm/cex-gen.o):
