#include <linux/module.h>
#include <linux/init.h>
#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/io.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <bcmutils.h>
#include <siutils.h>
#include <bcmnvram.h>
#include <flash.h>
#include <flashutl.h>
#include <sflash.h>
#include "bootnv.h"


typedef struct bootnv_pair {
	unsigned char na[256];
	unsigned char va[256];
} bootnv_pair_t;

static unsigned long start_addr = 0, end_addr = 0;	/* absolute addresses */
static unsigned int unused_offset = 0;			/* 'start_addr' is the base */
bootnv_pair_t entry[128];

static struct proc_dir_entry *proc_bootnv;
MODULE_DESCRIPTION("NVRAM on bootloader");
//add new objects at below
struct bootnv_object bootnv_tables[]=
{
        {"boot_ver",0}
};
static si_t *sih = NULL;
static chipcregs_t *cc = NULL;

#if 0//def BOOOTNV_DEBUG
static void dump_entries(void)
{
	int i;

	for (i=0; i<BOOTNV_TOTAL_ENTRY_CNT; i++) {
		if (entry[i].na == NULL)
			break;
		printk("pair[%d]=[%s, %s]\n", i, entry[i].na, entry[i].va);
	}
}

static void dump_text(void)
{
	int i = 0;

	printk("text[%d]=[", i);
	for (; i< BOOTNV_TOTAL_SIZE; i++) {
		if ((i> 0) && ((i % 0x10) == 0)) {
			printk("]\n[%d]=[", i);
		}
	}
	printk("]\n");
	printk("count=%d\n", i);
}
#endif

int build_entries(char *name, char *value)
{
	int i;
	for (i=0; i<BOOTNV_TOTAL_ENTRY_CNT; i++) {
		if (*entry[i].na && (strcmp(entry[i].na, name) != 0))
				continue;
	//	entry[i].na=(char *)kmalloc(strlen(name), GFP_ATOMIC);
	//	entry[i].va=(char *)kmalloc(strlen(value), GFP_ATOMIC);
		strcpy(entry[i].na, name);
		strcpy(entry[i].va, value);
		break;
	}
	return 1;
}

int get_all_entries(void)
{
	int len = 0;
	unsigned char *n;
	unsigned char *p = (unsigned char *)start_addr;
	unsigned char *last = (unsigned char *)end_addr;

	memset(entry, 0, sizeof(entry));
	while (p < last && *p != 0xff && (len = strlen(p)) > 0) {
		char ntmp[BOOTNV_ONE_ENTRY_SIZE];
		char *vtmp;
		n = p;
		strcpy(ntmp, n);
		vtmp=strchr(ntmp, '=');
		if (ntmp && vtmp) {
			*vtmp = 0; vtmp++;
			dprintk("%s = %s\n", ntmp, vtmp);
			build_entries(ntmp, vtmp);
		}
		/* Must end with '\0' for each pair */
		p += (len + 1);
		/* skip empty */
		while (*p == 0) p++;
	}
	unused_offset = p - (unsigned char *)start_addr;
	dprintk("unused_offset=%x\n", unused_offset);
	return 1;
}

char *get_entry_value(char *name)
{
	int i;

	get_all_entries();
	for (i=0; i<BOOTNV_TOTAL_ENTRY_CNT; i++) {
		if (entry[i].na == NULL)
			break;
		if (strcmp(entry[i].na, name) == 0)
			return entry[i].va;
	}
	return NULL;
}

int bootnv_addr_init(void)
{
	end_addr = FLASH_BASE + BOOT_SIZE_BYTES;
	start_addr = end_addr - BOOTNV_TOTAL_SIZE;
	dprintk("start=%#lx, end=%#lx\n", start_addr, end_addr);
	return 0;
}
int set_new_entry(char *str)
{
	int len = 0;
	unsigned char new[BOOTNV_ONE_ENTRY_SIZE];
	struct bootnv_object *obj;
	unsigned char *n, *v;
        unsigned char *p;

	if ((len = strlen(str)) > sizeof(new)) {
		dprintk(KERN_ERR "This new entry is too big. (length = %d > %d)\n", len, sizeof(new));
		return 0;
	}
	strcpy(new, str);
	len++;
	
	/* word alignment */
	if (len % 2) {
		new[len]=0;
		len++;
	}
	p=new;
	n = p;
        v = strchr(n, '=');
        *v = 0; v++;
	for(obj=bootnv_tables;obj->name;obj++)
        {
                if(!strcmp(n,obj->name))
                {
                	printk("This object is read only. Can't be written!!\n");
                        return 1;
        	}
        }

	printk(KERN_ERR "New entry '%s', length=%d\n", new, len);
	if ((unused_offset + len) > BOOTNV_TOTAL_SIZE)
		printk(KERN_ERR "There is no enough space available. (left %d bytes)\n", 
				BOOTNV_TOTAL_SIZE - unused_offset);
	else {	
		osl_t *osh;
		uint32 fltype = PFLASH;

		strcpy(new, str);
		osh = si_osh(sih);

		cc = (chipcregs_t *)si_setcoreidx(sih, 0/*SI_CC_IDX*/);
		if (cc) {
			/* Select SFLASH ? */
			fltype = R_REG(osh, &cc->capabilities) & CC_CAP_FLASH_MASK;
		}
		if (fltype == SFLASH_ST || fltype == SFLASH_AT) {
			int page_boundary=256 - unused_offset;
			if(unused_offset > 256) {
				page_boundary=(unused_offset/256 + 1)*256 - unused_offset;
			}
			if ( page_boundary < len){
				unsigned char new1[page_boundary];
				strncpy(new1, str, page_boundary);
				sflash_write(sih, cc,(uint)((start_addr - FLASH_BASE) + unused_offset), page_boundary, new1);

				while (sflash_poll(sih, cc, (uint)((start_addr - FLASH_BASE) + unused_offset)));
				unused_offset +=page_boundary;
				str +=page_boundary;
				strcpy(new, str);
				len=strlen(str)+1;
			}

			sflash_write(sih, cc, (uint)((start_addr - FLASH_BASE) + unused_offset), (uint) len, new);
			while (sflash_poll(sih, cc, (uint)((start_addr - FLASH_BASE) + unused_offset)));
		}
		else {
			flash_write((start_addr - FLASH_BASE) + unused_offset, (uint16*) new, (uint) len);
		}

	}
	
	return 1;
}

static int proc_read_bootnv(char *page, char **start, off_t off,
		int count, int *eof, void *data)
{
	int len = 0;
	int i;

	if (off > 0)
		return 0;

	get_all_entries();
	for (i=0; i<BOOTNV_TOTAL_ENTRY_CNT; i++) {
		if (entry[i].na == NULL)
			break;
		if (*(entry[i].va) == '\0')
			continue;
		len += sprintf(page+len, "%s\t%s\n", entry[i].na, entry[i].va);
	}
	len += sprintf(page+len, "\nTotal:%d, Used:%d, Free:%d  (byte)\n", BOOTNV_TOTAL_SIZE,
			unused_offset, BOOTNV_TOTAL_SIZE - unused_offset);
	*eof=1;
	return len;
}

static int proc_write_bootnv(struct file *file, const char *buffer,
		unsigned long count, void *data)
{
	char new[BOOTNV_ONE_ENTRY_SIZE];
	char *brk;
	char *name, *value, *entval;

	if (!count || count > sizeof(new)) {
		printk(KERN_ERR "This length range of new entry should be 1 ~ %d.\n", sizeof(new));
		return 0;
	}
	if (copy_from_user(new, buffer, count)) {
		return -EFAULT;
	}
	dprintk("%s: count=%lu, new=[%s]\n", __FUNCTION__, count, new);

	new[count-1] = '\0';
	name = new;
	brk = strpbrk(new, " \t");
	entval = get_entry_value(name);
	if(!brk) {	// unset
		if (!entval || strlen(entval) == 0)	/* not existent, or unset already */
			return count;
		new[count-1] = '=';
		new[count] = '\0';
	}
	else {		// set
		*brk = '\0';
		value = brk + 1;
		if (entval && strcmp(entval, value) == 0) /* already existent */
			return count;
		*brk = '=';
	}
	set_new_entry(new);
	return count;
}

static int __init bootnv_init(void)
{
	char nvmsg[40];
	uint32 fltype = PFLASH;
	osl_t *osh;

	/*
	 * Check for serial flash.
	 */
	sih = si_kattach(SI_OSH);
	ASSERT(sih);
	osh = si_osh(sih);

	cc = (chipcregs_t *)si_setcoreidx(sih, 0/*SI_CC_IDX*/);
	if (cc) {
		/* Select SFLASH ? */
		fltype = R_REG(osh, &cc->capabilities) & CC_CAP_FLASH_MASK;
	}

	bootnv_addr_init();
	/* /proc registration */
	proc_bootnv = create_proc_entry(PROC_BOOTNV, 0644, NULL);
	if (proc_bootnv == NULL) {
		remove_proc_entry(PROC_BOOTNV, &proc_root);
		printk(KERN_ERR "BOOTNV: Unable to create /proc/%s entry\n", PROC_BOOTNV);
		return -ENOMEM;
	}
	proc_bootnv->read_proc = proc_read_bootnv;
	proc_bootnv->write_proc = proc_write_bootnv;

	if (fltype == SFLASH_ST || fltype == SFLASH_AT) {
		sflash_init(sih, cc);
	}
	else {
		flash_init((void*)FLASH_BASE, nvmsg);
	}

	return 0;
}

static void __exit bootnv_exit(void)
{
	printk("exit\n");
	remove_proc_entry(PROC_BOOTNV, &proc_root);
}

module_init(bootnv_init);
module_exit(bootnv_exit);
