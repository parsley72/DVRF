#
# Makefile for Broadcom BCM947XX boards
#
# Copyright (c) 2010 Broadcom Corporation 
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# $Id: Makefile,v 1.2 2010/12/10 09:06:10 gavin.ke Exp $
#

SHARED := ../../../../../../shared

#BCM947XX_OBJS = $(addprefix $(SHARED)/, hndmips.o hndchipc.o linux_gpio.o sflash.o)
BCM947XX_OBJS = $(addprefix $(SHARED)/, hndmips.o hndchipc.o sflash.o)
BCM947XX_OBJS += gpio.o
BCM947XX_OBJS += $(addprefix $(SHARED)/nvram/, nvram.o)

EXTRA_CFLAGS += -DLINUX_HYBRID_POSTPROCESSING_REMOVAL

ifeq ($(CONFIG_PCI),y)
BCM947XX_OBJS += $(addprefix $(SHARED)/, hndpci.o) pcibios.o
endif

ifeq ($(CONFIG_WAPI),y)
EXTRA_CFLAGS += -DBCMWAPI_WAI
endif

ifeq ($(CONFIG_GENERIC_GPIO),y)
BCM947XX_OBJS += gen_gpio.o
endif


#BCM947XX_OBJS += setup.o prom.o time.o irq.o perfcntr.o gpio.o
BCM947XX_OBJS += setup.o prom.o time.o irq.o perfcntr.o

bcm947xx-objs += $(BCM947XX_OBJS)
obj-y += bcm947xx.o
