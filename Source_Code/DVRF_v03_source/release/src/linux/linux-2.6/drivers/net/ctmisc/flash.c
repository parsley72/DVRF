/*
 * flashutl.c - Flash Read/write/Erase routines
 *
 * Copyright (C) 2010, Broadcom Corporation. All Rights Reserved.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: flash.c,v 1.12 2008/09/16 07:58:15 jack Exp $
 */

#include <typedefs.h>
#include <osl.h>

#define DECLARE_FLASHES
#include <bcmutils.h>
#include <siutils.h>
#include <sbconfig.h>
#include <hndsoc.h>
#include <flash.h>
#include <sflash.h>
#include <flashutl.h>
#include <bcmnvram.h>

#define DPRINT(x) printk x

#define ERR2	0x30 /* Mask for err UNUSED */
#define DONE	0x80 /* Mask for done */
#define WBUFSIZE 32  /* Write Buffer size */
#define FLASH_TRIES 4000000 /* retry count */
#define CMD_ADDR ((unsigned long)0xFFFFFFFF)

/* 'which' param for block() */
#define BLOCK_BASE	0  /* Base of block */
#define BLOCK_LIM	1  /* Limit of block */

#define FLASH_ADDR(off) ((unsigned long)flashutl_base + (off))

/* Local vars */
static si_t *sih = NULL;
static chipcregs_t *cc = NULL;
/* Private global state */
static struct sflash sflash;

/* Global vars */
uint8		*flashutl_base	= NULL;
flash_desc_t	*flashutl_desc	= NULL;
flash_cmds_t	*flashutl_cmd	= NULL;
uint8 flashutl_wsz = sizeof(uint16);

static void		scmd(uint16 cmd, unsigned long off);
static void		cmd(uint16 cmd, unsigned long off);
static void		flash_reset(void);
static int		flash_poll(unsigned long off, uint16 data);
static unsigned long	block(unsigned long addr, int which);
static int	flash_eraseblk(unsigned long off);
int	flash_write(unsigned long off, uint8 *src, uint nbytes);
static uint16 INLINE flash_readword(unsigned long addr);
static void INLINE flash_writeword(unsigned long addr, uint16 data);

int sysFlashErase(uint off, unsigned int numbytes);

int
flash_init(char *base_addr, char *flash_str)
{
	sysFlashInit(flash_str);
	return 0;
}

/* Read the flash ID and set the globals */
int
sysFlashInit(char *flash_str)
{
	osl_t *osh;
	uint32 fltype = PFLASH;
	uint16 flash_vendid = 0;
	uint16 flash_devid = 0;
	int idx;
	struct sflash *sflash;
	uint32 flash_config;


	/*
	 * Check for serial flash.
	 */
	sih = si_kattach(SI_OSH);
	ASSERT(sih);

	osh = si_osh(sih);

	flashutl_base = (uint8*)OSL_UNCACHED(SI_FLASH1);
	flashutl_wsz = sizeof(uint16);
	cc = (chipcregs_t *)si_setcore(sih, CC_CORE_ID, 0);
	if (cc) {
		flashutl_base = (uint8*)OSL_UNCACHED(SI_FLASH2);
		flashutl_wsz = (R_REG(osh, &flash_config) & CC_CFG_DS) ?
		        sizeof(uint16) : sizeof(uint8);
		/* Select SFLASH ? */
		fltype = R_REG(osh, &cc->capabilities) & CC_CAP_FLASH_MASK;
		if (fltype == SFLASH_ST || fltype == SFLASH_AT) {
			sflash = sflash_init(sih, cc);
			flashutl_cmd = &sflash_cmd_t;
			flashutl_desc = &sflash_desc;
			flashutl_desc->size = sflash->size;
			if (flash_str) 
				 sprintf(flash_str, "SFLASH %d kB", sflash->size/1024);
			return (0);
		}
	}

	printk("flashutl_base=%lx flashutl_wsz=%d, sizeof(unit8)=%d\n", (unsigned long)flashutl_base, flashutl_wsz, sizeof(uint8));

	ASSERT(flashutl_wsz == sizeof(uint8) || flashutl_wsz == sizeof(uint16));

	/*
	 * Parallel flash support
	 *  Some flashes have different unlock addresses, try each it turn
	 */
        /* 
         * Some flashes have different unlock addresses, try each it turn
         */
#if 1
        idx = sizeof(flash_cmds)/sizeof(flash_cmds_t) - 2;
        flashutl_cmd = &flash_cmds[idx--];
 
        while(flashutl_cmd->type) {
#else
	for (idx = 0;
	     fltype == PFLASH && idx < ARRAYSIZE(flash_cmds);
	     idx ++) {
		printk("\nidx=%d\n", idx);
		flashutl_cmd = &flash_cmds[idx];
#endif
		if (flashutl_cmd->type == OLD)
			continue;

		if (flashutl_cmd->read_id)
			cmd(flashutl_cmd->read_id, CMD_ADDR);

#ifdef MIPSEB
		flash_vendid = flash_readword(FLASH_ADDR(2));
		flash_devid = flash_readword(FLASH_ADDR(0));
#else
		flash_vendid = flash_readword(FLASH_ADDR(0));
		flash_devid = flash_readword(FLASH_ADDR(2));
#endif /* MIPSEB */

		/* Funky AMD, uses 3 byte device ID so use first byte (4th addr) to
		 * identify it is a 3-byte ID and use the next two bytes (5th & 6th addr)
		 * to form a word for unique identification of format xxyy, where
		 * xx = 5th addr and yy = 6th addr
		 */
#if 01
		if ((flash_vendid == 1) && (flash_devid == 0x227e)) {
			printk("Get real devid\n");
			/* Get real devid */
			uint16 flash_devid_5th;
#ifdef MIPSEB
			flash_devid_5th = flash_readword(FLASH_ADDR(0x1e)) << 8;
			flash_devid = (flash_readword(FLASH_ADDR(0x1c)) & 0xff) | flash_devid_5th;
#else
			flash_devid_5th = flash_readword(FLASH_ADDR(0x1c)) << 8;
			flash_devid = (flash_readword(FLASH_ADDR(0x1e)) & 0xff) | flash_devid_5th;
#endif /* MIPSEB */
		}
#endif
		printk("Try %d: vendor id = 0x%04X, device id = 0x%04X\n", idx+2, flash_vendid, flash_devid);
		flashutl_desc = flashes;

                if(flashutl_wsz == sizeof(uint8)){
                        while (flashutl_desc->mfgid != 0 &&
                                   !(flashutl_desc->mfgid == flash_vendid &&
                                 (flashutl_desc->devid & 0xff) == flash_devid)) {
                                flashutl_desc++;
                        }
                }else{
                        while (flashutl_desc->mfgid != 0 &&
                                   !(flashutl_desc->mfgid == flash_vendid &&
                                 flashutl_desc->devid == flash_devid)) {
                                flashutl_desc++;
                        }
                }
		if (flashutl_desc->mfgid != 0)
			break;

                if(idx < 0) 
                        break;
                else
                        flashutl_cmd = &flash_cmds[idx--];
	}

	if (flashutl_desc->mfgid == 0) {
		flashutl_desc = NULL;
		flashutl_cmd = NULL;
	} else {
		flashutl_cmd = flash_cmds;
		while (flashutl_cmd->type != 0 && flashutl_cmd->type != flashutl_desc->type)
			flashutl_cmd++;
		if (flashutl_cmd->type == 0)
			flashutl_cmd = NULL;
	}

	if (flashutl_cmd != NULL) {
		flash_reset();
	}

	if (flashutl_desc == NULL) {
		if (flash_str)
			sprintf(flash_str, "UNKNOWN 0x%x 0x%x", flash_vendid, flash_devid);
		DPRINT(("Flash type UNKNOWN\n"));
		return 1;
	}

	if (flash_str)
		strcpy(flash_str, flashutl_desc->desc);
	DPRINT(("Flash type \"%s\"\n", flashutl_desc->desc));

	return 0;
}

static int
flash_eraseblk(unsigned long addr)
{
	unsigned long a;
	uint16 st;

	a = (unsigned long)addr;
	if (a >= flashutl_desc->size)
		return 1;

	a = block(a, BLOCK_BASE);

	/* Ensure blocks are unlocked (for intel chips) */
	if (flashutl_cmd->type == BSC) {
		scmd((unsigned char)INTEL_UNLOCK1, a);
		scmd((unsigned char)INTEL_UNLOCK2, a);
	}

	if (flashutl_cmd->pre_erase)
		cmd(flashutl_cmd->pre_erase, CMD_ADDR);
	if (flashutl_cmd->erase_block)
		cmd(flashutl_cmd->erase_block, a);
	if (flashutl_cmd->confirm)
		scmd(flashutl_cmd->confirm, a);

	if (flashutl_wsz == sizeof(uint8))
		st = flash_poll(a, 0xff);
	else
		st = flash_poll(a, 0xffff);

	flash_reset();

	if (st) {
		DPRINT(("Erase of block 0x%08lx-0x%08lx failed\n",
			a, block((unsigned long)addr, BLOCK_LIM)));
		return st;
	}

	//DPRINT(("Erase of block 0x%08lx-0x%08lx done\n", a, block((unsigned long)addr, BLOCK_LIM)));

	return 0;
}

int
flash_write(unsigned long off, uint8 *src, uint nbytes)
{
	uint8 *dest;
	uint16 st, data;
	uint i, len;

	ASSERT(flashutl_desc != NULL);

	if (off >= flashutl_desc->size)
		return 1;

	ASSERT(!(off & (flashutl_wsz - 1)));

	dest = (uint8*)FLASH_ADDR(off);
	st = 0;

	while (nbytes) {
		//if ((flashutl_desc->type == SCS) &&
		//    flashutl_cmd->write_buf &&
		//    ((off & (WBUFSIZE - 1)) == 0)) {
		if(0) {
			/* issue write command */
			if (flashutl_cmd->write_buf)
				cmd(flashutl_cmd->write_buf, off);
			if ((st = flash_poll(off, DONE)))
				continue;

			len = MIN(nbytes, WBUFSIZE);

#ifndef MIPSEB
			/* write (length - 1) */
			cmd(len / sizeof(uint16) - 1, off);

			/* write data */
			for (i = 0; i < len; i += sizeof(uint16),
			             dest += sizeof(uint16), src += sizeof(uint16))
				*(uint16 *)dest = *(uint16 *)src;
#else
			/*
			 * BCM4710 endianness is word consistent but
			 * byte/short scrambled. This write buffer
			 * mechanism appears to be sensitive to the
			 * order of the addresses hence we need to
			 * unscramble them. We may also need to pad
			 * the source with two bytes of 0xffff in case
			 * an odd number of shorts are presented.
			 */

			/* write (padded length - 1) */
			cmd((ROUNDUP(len, sizeof(uint32)) / sizeof(uint16)) - 1, off);

			/* write data (plus pad if necessary) */
			for (i = 0; i < ROUNDUP(len, sizeof(uint32)); i += sizeof(uint32),
			             dest += sizeof(uint32), src += sizeof(uint32)) {
				*((uint16 *)dest + 1) = ((i + sizeof(uint16)) < len) ?
				        *((uint16 *)src + 1) : 0xffff;
				*(uint16 *)dest = *(uint16 *)src;
			}
#endif /* MIPSEB */

			/* write confirm */
			if (flashutl_cmd->confirm)
				cmd(flashutl_cmd->confirm, off);

			if ((st = flash_poll(off, DONE)))
				break;
		} else {
			/* issue write command */
			if (flashutl_cmd->write_word)
				cmd(flashutl_cmd->write_word, CMD_ADDR);

			/* write data */
			data = flash_readword((unsigned long)src);
			flash_writeword((unsigned long)dest, data);

			/* poll for done */
			if ((st = flash_poll(off, data)))
				break;

			len = MIN(nbytes, flashutl_wsz);
			dest += len;
			src += len;
		}

		nbytes -= len;
		off += len;
	}

	flash_reset();

	return st;
}

static uint16 INLINE
flash_readword(unsigned long addr)
{
	uint8 a;
	uint16 b;

	if (flashutl_wsz == sizeof(uint8)) {
		a = *(uint8*)addr;
		//printk("flash_readword(): 8, addr(%lx)= data(%x)\n", addr, a);
		return a;
	}
	else {
		b = *(uint16*)addr;
		//printk("flash_readword(): 16, addr(%lx)= data(%x)\n", addr, b);
		return b;
	}
}

static void INLINE
flash_writeword(unsigned long addr, uint16 data)
{
	if (flashutl_wsz == sizeof(uint8)) {
		*(uint8*)addr = (uint8)data;
		//printk("flash_writeword(): 8, addr(%lx) = data(%x)\n", addr, data);
	}
	else {
		*(uint16*)addr = data;
		//printk("flash_writeword(): 16, addr(%lx = data(%x)\n", addr, data);
	}
}

/* Writes a single command to the flash. */
static void
scmd(uint16 cmd, unsigned long off)
{
	/*  cmd |= cmd << 8; */
	//printk("scmd(%x,%lx)\n", cmd, off);
	flash_writeword(FLASH_ADDR(off), cmd);
}

/* Writes a command to flash, performing an unlock if needed. */
static void
cmd(uint16 cmd, unsigned long off)
{
	int i;
	unlock_cmd_t *ul = NULL;

	printk("cmd(%x,%lx)\n", cmd, off);

	ASSERT(flashutl_cmd != NULL);

	switch (flashutl_cmd->type) {
	case AMD:
		ul = &unlock_cmd_amd;
		break;
	case SST:
		ul = &unlock_cmd_sst;
		break;
	default:
		break;
	}

	if (flashutl_cmd->need_unlock) {
		ASSERT(ul);
		for (i = 0; i < UNLOCK_CMD_WORDS; i++) {
			//printk("Need unlock (%d):\n", i);
			flash_writeword(FLASH_ADDR(ul->addr[i]), ul->cmd[i]);
		}
	}

	/* cmd |= cmd << 8; */

	if (off == CMD_ADDR) {
		switch (flashutl_cmd->type) {
		case AMD:
			off = AMD_CMD;
			break;
		case SST:
			off = SST_CMD;
			break;
		default:
			off = 0;
			break;
		}
	}

#ifdef MIPSEB
	off ^= 2;
#endif /* MIPSEB */

	flash_writeword(FLASH_ADDR(off), cmd);
}

static void
flash_reset()
{
	ASSERT(flashutl_desc != NULL);

	printk("flash_reset():\n");

	if (flashutl_cmd->clear_csr)
		scmd(flashutl_cmd->clear_csr, 0);
	if (flashutl_cmd->read_array)
		scmd(flashutl_cmd->read_array, 0);
}

static int
flash_poll(unsigned long off, uint16 data)
{
	unsigned long addr;
	int cnt = FLASH_TRIES;
	uint16 st;

	//printk("flash_poll(%lx,%x):\n", off, data);

	ASSERT(flashutl_desc != NULL);

	if (flashutl_desc->type == AMD || flashutl_desc->type == SST) {
		/* AMD style poll checkes the address being written */
		addr = FLASH_ADDR(off);
		while ((st = flash_readword(addr)) != data && cnt != 0)
			cnt--;
		if (cnt == 0) {
			DPRINT(("flash_poll: timeout, off %lx, read 0x%x, expected 0x%x\n",
			        off, st, data));
			return -1;
		}
	} else {
		/* INTEL style poll is at second word of the block being written */
		addr = FLASH_ADDR(block(off, BLOCK_BASE)+sizeof(uint16));
		while (((st = flash_readword(addr)) & DONE) == 0 && cnt != 0)
			cnt--;
		if (cnt == 0) {
			DPRINT(("flash_poll: timeout, error status = 0x%x\n", st));
			return -1;
		}
	}

	return 0;
}

static unsigned long
block(unsigned long addr, int which)
{
	unsigned long b, l, sb;
	uint* sblocks;
	int i;

	ASSERT(flashutl_desc != NULL);

	ASSERT(addr < (unsigned long)flashutl_desc->size);

	b = addr / flashutl_desc->bsize;
	/* check for an address a full size block */
	if (b >= flashutl_desc->ff && b <= flashutl_desc->lf) {
		if (which == BLOCK_LIM) b++;
		return (b * flashutl_desc->bsize);
	}

	/* search for the sub-block */
	if (flashutl_desc->ff == 0) {
		/* sub blocks are at the end of the flash */
		sb = flashutl_desc->bsize * (flashutl_desc->lf + 1);
	} else {
		/* sub blocks are at the start of the flash */
		sb = 0;
	}

	sblocks = flashutl_desc->subblocks;
	for (i = 0; i < flashutl_desc->nsub; i++) {
		b = sb + sblocks[i];
		l = sb + sblocks[i+1];
		if (addr >= b && addr < l) {
			if (which == BLOCK_BASE)
				return b;
			else
				return l;
		}
	}

	return 0;
}

void
nvWrite(unsigned short *data, unsigned int len)
{
	uint off = flashutl_desc->size - NVRAM_SPACE;
	sysFlashWrite(off, (uchar*)data, len);
}

void
nvWriteChars(unsigned char *data, unsigned int len)
{
	uint off = flashutl_desc->size - NVRAM_SPACE;
	int err;

	if (flashutl_cmd->type == SFLASH)
		err = sflash_commit(sih, cc, off, len, data);
	else /* PFLASH */
		err = flash_write(off, data, len);

	if (err)
		DPRINT(("nvWriteChars failed\n"));
	else
		DPRINT(("nvWriteChars succeeded\n"));
}

int
sysFlashErase(uint off, unsigned int numbytes)
{
	unsigned long end = off + numbytes;
	int err = 0;

	if (flashutl_cmd->type == SFLASH) {
		err = sflash_commit(sih, cc, off, numbytes, NULL);
	} else {
		while (off < end) {
			err = flash_eraseblk(off);
			if (err)
				break;
			off = block(off, BLOCK_LIM);
		}
	}

	if (err)
		DPRINT(("Block erase at 0x%x failed\n", off));
	else
		DPRINT(("Done\n"));

	return !err;
}

int
sysFlashWrite(uint off, uchar *src, uint numbytes)
{
	int err;

	//DPRINT(("Writing 0x%x bytes to flash @0x%x ...\n", (unsigned int)numbytes, off));

	if (flashutl_cmd->type == SFLASH)
		err = sflash_commit(sih, cc, off, numbytes, src);
	else {
		if (!sysFlashErase(off, numbytes))
			return 0;
		err = flash_write(off, src, numbytes);
	}

	if (err)
		DPRINT(("Flash write failed\n"));
	else
		DPRINT(("Flash write succeeded\n"));

	return !err;
}

int
sysFlashRead(uint off, uchar *buf, uint numbytes)
{
	uint read, total_read = 0;

	if (flashutl_cmd->type == SFLASH) {
		while (numbytes) {
			read = sflash_read(sih, cc, off, numbytes, buf);
			numbytes -= read;
			buf += read;
			off += read;
			total_read += read;
		}
	} else {
		ASSERT(!(off & (flashutl_wsz - 1)));
		ASSERT(!(numbytes & (flashutl_wsz - 1)));

		while (numbytes) {
			flash_writeword((unsigned long)buf, flash_readword(FLASH_ADDR(off)));
			numbytes -= flashutl_wsz;
			buf += flashutl_wsz;
			off += flashutl_wsz;
			total_read += flashutl_wsz;
		}
	}

	return (total_read);
}

/* Issue a serial flash command */
static INLINE void
sflash_cmd(osl_t *osh, chipcregs_t *cc, uint opcode)
{
	W_REG(osh, &cc->flashcontrol, SFLASH_START | opcode);
	while (R_REG(osh, &cc->flashcontrol) & SFLASH_BUSY);
}

struct sflash *
sflash_init(si_t *sih, chipcregs_t *cc)
{
	uint32 id, id2;
	osl_t *osh;

	ASSERT(sih);

	osh = si_osh(sih);

	bzero(&sflash, sizeof(sflash));

	sflash.type = sih->cccaps & CC_CAP_FLASH_MASK;
	
	printk("%s: sflash type 0x%x\n", __FUNCTION__, sflash.type);
	
	switch (sflash.type) {
	case SFLASH_ST:
		/* Probe for ST chips */
		sflash_cmd(osh, cc, SFLASH_ST_DP);
		sflash_cmd(osh, cc, SFLASH_ST_RES);
		id = R_REG(osh, &cc->flashdata);
		printk("%s: sflash type 0x%x\n", __FUNCTION__, id);
		switch (id) {
		case 0x11:
			/* ST M25P20 2 Mbit Serial Flash */
			sflash.blocksize = 64 * 1024;
			sflash.numblocks = 4;
			break;
		case 0x12:
			/* ST M25P40 4 Mbit Serial Flash */
			sflash.blocksize = 64 * 1024;
			sflash.numblocks = 8;
			break;
		case 0x13:
			/* ST M25P80 8 Mbit Serial Flash */
			sflash.blocksize = 64 * 1024;
			sflash.numblocks = 16;
			break;
		case 0x14:
			/* ST M25P16 16 Mbit Serial Flash */
			sflash.blocksize = 64 * 1024;
			sflash.numblocks = 32;
			break;
		case 0x15:
			/* ST M25P32 32 Mbit Serial Flash */
			sflash.blocksize = 64 * 1024;
			sflash.numblocks = 64;
			break;
		case 0x16:
			/* ST M25P64 64 Mbit Serial Flash */
			sflash.blocksize = 64 * 1024;
			sflash.numblocks = 128;
			break;	
		case 0x17:
			/* ST M25P64 128 Mbit/16M bytes Serial Flash */
			sflash.blocksize = 64 * 1024;
			sflash.numblocks = 256;
			break;

		case 0xbf:
			W_REG(osh, &cc->flashaddress, 1);
			sflash_cmd(osh, cc, SFLASH_ST_RES);
			id2 = R_REG(osh, &cc->flashdata);
			if (id2 == 0x44) {
				/* SST M25VF80 4 Mbit Serial Flash */
				sflash.blocksize = 64 * 1024;
				sflash.numblocks = 8;
			}
			break;
		}
		break;

	case SFLASH_AT:
		/* Probe for Atmel chips */
		sflash_cmd(osh, cc, SFLASH_AT_STATUS);
		id = R_REG(osh, &cc->flashdata) & 0x3c;
		switch (id) {
		case 0xc:
			/* Atmel AT45DB011 1Mbit Serial Flash */
			sflash.blocksize = 256;
			sflash.numblocks = 512;
			break;
		case 0x14:
			/* Atmel AT45DB021 2Mbit Serial Flash */
			sflash.blocksize = 256;
			sflash.numblocks = 1024;
			break;
		case 0x1c:
			/* Atmel AT45DB041 4Mbit Serial Flash */
			sflash.blocksize = 256;
			sflash.numblocks = 2048;
			break;
		case 0x24:
			/* Atmel AT45DB081 8Mbit Serial Flash */
			sflash.blocksize = 256;
			sflash.numblocks = 4096;
			break;
		case 0x2c:
			/* Atmel AT45DB161 16Mbit Serial Flash */
			sflash.blocksize = 512;
			sflash.numblocks = 4096;
			break;
		case 0x34:
			/* Atmel AT45DB321 32Mbit Serial Flash */
			sflash.blocksize = 512;
			sflash.numblocks = 8192;
			break;
		case 0x3c:
			/* Atmel AT45DB642 64Mbit Serial Flash */
			sflash.blocksize = 1024;
			sflash.numblocks = 8192;
			break;
		}
		break;
	}

	sflash.size = sflash.blocksize * sflash.numblocks;
	return sflash.size ? &sflash : NULL;
}

int
sflash_read(si_t *sih, chipcregs_t *cc, uint offset, uint len, uchar *buf)
{
	return 0;
}

int
sflash_commit(si_t *sih, chipcregs_t *cc, uint offset, uint len, const uchar *buf)
{
	return 0;
}

#define	ST_RETRIES	3

int
sflash_write(si_t *sih, chipcregs_t *cc, uint offset, uint length, const uchar *buffer)
{
	struct sflash *sfl;
	uint off = offset, len = length;
	const uchar *buf = buffer;
	int ret = 0, try = 0;
	bool is4712b0;
	uint32 page, byte, mask;
	osl_t *osh;

	ASSERT(sih);

	osh = si_osh(sih);

	if (!len)
		return 0;

	sfl = &sflash;
	if ((off + len) > sfl->size)
		return -22;

	switch (sfl->type) {
	case SFLASH_ST:
		is4712b0 = (sih->chip == 0x4712/*BCM4712_CHIP_ID*/) && (sih->chiprev == 3);
		/* Enable writes */
retry:		sflash_cmd(osh, cc, SFLASH_ST_WREN);
		off = offset;
		len = length;
		buf = buffer;
		try++;
		if (is4712b0) {
			mask = 1 << 14;
			W_REG(osh, &cc->flashaddress, off);
			W_REG(osh, &cc->flashdata, *buf++);
			/* Set chip select */
			OR_REG(osh, &cc->gpioout, mask);
			/* Issue a page program with the first byte */
			sflash_cmd(osh, cc, SFLASH_ST_PP);
			ret = 1;
			off++;
			len--;
			while (len > 0) {
				if ((off & 255) == 0) {
					/* Page boundary, drop cs and return */
					AND_REG(osh, &cc->gpioout, ~mask);
					OSL_DELAY(1);
					if (!sflash_poll(sih, cc, off)) {
						/* Flash rejected command */
						if (try <= ST_RETRIES)
							goto retry;
						else
							return -11;
					}
					return ret;
				} else {
					/* Write single byte */
					sflash_cmd(osh, cc, *buf++);
				}
				ret++;
				off++;
				len--;
			}
			/* All done, drop cs */
			AND_REG(osh, &cc->gpioout, ~mask);
			OSL_DELAY(1);
			if (!sflash_poll(sih, cc, off)) {
				/* Flash rejected command */
				if (try <= ST_RETRIES)
					goto retry;
				else
					return -12;
			}
		} else if (sih->ccrev >= 20) {
			W_REG(NULL, &cc->flashaddress, off);
			W_REG(NULL, &cc->flashdata, *buf++);
			/* Issue a page program with CSA bit set */
			sflash_cmd(osh, cc, SFLASH_ST_CSA | SFLASH_ST_PP);
			ret = 1;
			off++;
			len--;
			while (len > 0) {
				if ((off & 255) == 0) {
					/* Page boundary, poll droping cs and return */
					W_REG(NULL, &cc->flashcontrol, 0);
					OSL_DELAY(1);
					if (sflash_poll(sih, cc, off) == 0) {
						/* Flash rejected command */
						printk(("sflash: pp retrejected, try: %d,"
						         " off: %d/%d, len: %d/%d, ret:"
						         "%d\n", try, off, offset, len,
						         length, ret));
						if (try <= ST_RETRIES)
							goto retry;
						else
							return -11;
					}
					return ret;
				} else {
					/* Write single byte */
					sflash_cmd(osh, cc, SFLASH_ST_CSA | *buf++);
				}
				ret++;
				off++;
				len--;
			}
			/* All done, drop cs & poll */
			W_REG(NULL, &cc->flashcontrol, 0);
			OSL_DELAY(1);
			if (sflash_poll(sih, cc, off) == 0) {
				/* Flash rejected command */
				printk(("sflash: pp rejected, try: %d, off: %d/%d,"
				         " len: %d/%d, ret: %d\n",
				         try, off, offset, len, length, ret));
				if (try <= ST_RETRIES)
					goto retry;
				else
					return -12;
			}
		} else {
			ret = 1;
			W_REG(osh, &cc->flashaddress, off);
			W_REG(osh, &cc->flashdata, *buf);
			/* Page program */
			sflash_cmd(osh, cc, SFLASH_ST_PP);
		}
		break;
	case SFLASH_AT:
		mask = sfl->blocksize - 1;
		page = (off & ~mask) << 1;
		byte = off & mask;
		/* Read main memory page into buffer 1 */
		if (byte || (len < sfl->blocksize)) {
			W_REG(osh, &cc->flashaddress, page);
			sflash_cmd(osh, cc, SFLASH_AT_BUF1_LOAD);
			/* 250 us for AT45DB321B */
			SPINWAIT(sflash_poll(sih, cc, off), 1000);
			ASSERT(!sflash_poll(sih, cc, off));
		}
		/* Write into buffer 1 */
		for (ret = 0; (ret < (int)len) && (byte < sfl->blocksize); ret++) {
			W_REG(osh, &cc->flashaddress, byte++);
			W_REG(osh, &cc->flashdata, *buf++);
			sflash_cmd(osh, cc, SFLASH_AT_BUF1_WRITE);
		}
		/* Write buffer 1 into main memory page */
		W_REG(osh, &cc->flashaddress, page);
		sflash_cmd(osh, cc, SFLASH_AT_BUF1_PROGRAM);
		break;
	}
	
	return ret;
}

int
sflash_poll(si_t *sih, chipcregs_t *cc, uint offset)
{
	osl_t *osh;

	ASSERT(sih);

	osh = si_osh(sih);

	if (offset >= sflash.size)
		return -22;

	switch (sflash.type) {
	case SFLASH_ST:
		/* Check for ST Write In Progress bit */
		sflash_cmd(osh, cc, SFLASH_ST_RDSR);
		return R_REG(osh, &cc->flashdata) & SFLASH_ST_WIP;
	case SFLASH_AT:
		/* Check for Atmel Ready bit */
		sflash_cmd(osh, cc, SFLASH_AT_STATUS);
		return !(R_REG(osh, &cc->flashdata) & SFLASH_AT_READY);
	}

	return 0;
}
