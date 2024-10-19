#include <linux/module.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/miscdevice.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

#include <typedefs.h>
#include <bcmutils.h>
#include <siutils.h>
#include <bcmdevs.h>
#include <bcmnvram.h>
#include <flash.h>
#include <flashutl.h>
#include <cymac.h>
#include <cy_conf.h>
#include <sflash.h>

#include "ext_io.h"

#define FLASH_BASE                0xbc000000


#if 0
  #define DEBUGP printk
#else
  #define DEBUGP(format, args...)
#endif

//static devfs_handle_t ctmisc_handle = NULL;
//extern uint8 flash_data_width;
extern uint8 flashutl_wsz;

#ifdef DUAL_IMAGE_SUPPORT
extern size_t image1_stable_loc;
extern size_t image2_stable_loc;
#endif

typedef union {
#ifdef WRITE_MAC_SUPPORT
	struct {
		int index;
		unsigned char maclist[RESERVE_MAC][PER_MAC_LEN];
	} mac;
#endif
#ifdef EOU_SUPPORT
	struct {
		int index;
		unsigned char eoulist[RESERVE_EOU_KEY][PER_EOU_KEY_LEN];
	} eou;
#endif
#ifdef WRITE_SN_SUPPORT
	struct {
		int index;
		unsigned char snlist[RESERVE_SN][PER_SN_LEN];
	} sn;
#endif
#ifdef T_CERT_SUPPORT
	struct {
		int index;
		unsigned char tcertlist[RESERVE_T_CERT][PER_T_CERT_LEN];
	} tcert;
#endif
#ifdef DUAL_IMAGE_SUPPORT
	struct {
		int index;
		unsigned char stablelist[RESERVE_STABLE][PER_STABLE_LEN];
	} stable;
	struct {
		int index;
		unsigned char trylist[RESERVE_TRY][PER_TRY_LEN];
	} try;
#endif
#ifdef WRITE_COUNTRY_SUPPORT
	struct {
		int index;
		unsigned char countrylist[RESERVE_COUNTRY][PER_COUNTRY_LEN];
	} country;
	struct {
		int index;
		unsigned char country_code_2g_list[RESERVE_COUNTRY][PER_COUNTRY_LEN];
	} country_code_2g;
	struct {
		int index;
		unsigned char country_code_5g_list[RESERVE_COUNTRY][PER_COUNTRY_LEN];
	} country_code_5g;
#endif

#ifdef WRITE_PA_SUPPORT
	/* 2.4G PA value */
        struct {
                int index;
                unsigned char pa0list[RESERVE_PA0][PER_PA0_LEN];
        } pa2ga0;
        struct {
                int index;
                unsigned char pa1list[RESERVE_PA1][PER_PA1_LEN];
        } pa2ga1;
        struct {
                int index;
                unsigned char pa0idxvallist[RESERVE_PA0IDXVAL][PER_PA0IDXVAL_LEN];
        } pa2ga0idxval;
        struct {
                int index;
                unsigned char pa1idxvallist[RESERVE_PA1IDXVAL][PER_PA1IDXVAL_LEN];
        } pa2ga1idxval;

	/* 5G PA high value */
        struct {
                int index;
                unsigned char pa0list[RESERVE_PA0][PER_PA0_LEN];
        } pa5gha0;
        struct {
                int index;
                unsigned char pa1list[RESERVE_PA1][PER_PA1_LEN];
        } pa5gha1;
        struct {
                int index;
                unsigned char pa0idxvallist[RESERVE_PA0IDXVAL][PER_PA0IDXVAL_LEN];
        } pa5gha0idxval;
        struct {
                int index;
                unsigned char pa1idxvallist[RESERVE_PA1IDXVAL][PER_PA1IDXVAL_LEN];
        } pa5gha1idxval;
	//Jemmy add for 5G antx2 2010.8.20
        struct {
                int index;
                unsigned char pa2idxvallist[RESERVE_PA2IDXVAL][PER_PA2IDXVAL_LEN];
        } pa5gha2idxval;

        /* 5G PA low value */
        struct {
                int index;
                unsigned char pa0list[RESERVE_PA0][PER_PA0_LEN];
        } pa5gla0;
        struct {
                int index;
                unsigned char pa1list[RESERVE_PA1][PER_PA1_LEN];
        } pa5gla1;
        struct {
                int index;
                unsigned char pa0idxvallist[RESERVE_PA0IDXVAL][PER_PA0IDXVAL_LEN];
        } pa5gla0idxval;
        struct {
                int index;
                unsigned char pa1idxvallist[RESERVE_PA1IDXVAL][PER_PA1IDXVAL_LEN];
        } pa5gla1idxval;
	//Jemmy add for 5G antx2 2010.8.20
        struct {
                int index;
                unsigned char pa2idxvallist[RESERVE_PA2IDXVAL][PER_PA2IDXVAL_LEN];
        } pa5gla2idxval;

        /* 5G PA middle value */
        struct {
                int index;
                unsigned char pa0list[RESERVE_PA0][PER_PA0_LEN];
        } pa5ga0;
        struct {
                int index;
                unsigned char pa1list[RESERVE_PA1][PER_PA1_LEN];
        } pa5ga1;
        struct {
                int index;
                unsigned char pa0idxvallist[RESERVE_PA0IDXVAL][PER_PA0IDXVAL_LEN];
        } pa5ga0idxval;
        struct {
                int index;
                unsigned char pa1idxvallist[RESERVE_PA1IDXVAL][PER_PA1IDXVAL_LEN];
        } pa5ga1idxval;
	//Jemmy add for 5G antx2 2010.8.20 
       	struct {
                int index;
                unsigned char pa2idxvallist[RESERVE_PA2IDXVAL][PER_PA2IDXVAL_LEN];
        } pa5ga2idxval;

#endif
} MYDATA;

extern int flash_write(unsigned long off, uint16 *src, uint nbytes);
extern int flash_init(void* base_addr, char *flash_str);
struct sflash *sflash_init(si_t *sih, chipcregs_t *cc);
extern int sflash_write(si_t *sih, chipcregs_t *cc, uint offset, uint length, const uchar *buffer);

int ctmisc_open (struct inode *inode, struct file *filp)
{
	DEBUGP("%s(): \n", __FUNCTION__);
	return 0;
}

ssize_t ctmisc_read(struct file *filp, char *buf, size_t count, loff_t *ppos)
{
	DEBUGP("%s(): \n", __FUNCTION__);
	return 0;
}

ssize_t ctmisc_write(struct file *filp, const char *buf, size_t count, loff_t *ppos)
{
	DEBUGP("%s(): \n", __FUNCTION__);
	return 0;
}

int ctmisc_release(struct inode* inode, struct file *flip)
{
	DEBUGP("%s(): \n", __FUNCTION__);
	return 0;
}

int ctmisc_flush(struct file *flip)
{
	DEBUGP("%s(): \n", __FUNCTION__);
	return 0;
}

struct table {
        int cmd;
        char *desc;
        int count;
        int len;
};

struct table tables[] = {
#ifdef WRITE_MAC_SUPPORT
        { GET_MAC,	"MAC",		RESERVE_MAC,            PER_MAC_LEN},
        { SET_MAC,	"MAC",		RESERVE_MAC,            PER_MAC_LEN},
#endif 
#ifdef EOU_SUPPORT
        { GET_EOU,	"EOU",		RESERVE_EOU_KEY,        PER_EOU_KEY_LEN},
        { SET_EOU,	"EOU",		RESERVE_EOU_KEY,        PER_EOU_KEY_LEN},
#endif
#ifdef WRITE_SN_SUPPORT
	{ GET_SN,	"SN",		RESERVE_SN,             PER_SN_LEN},
        { SET_SN,	"SN",		RESERVE_SN,             PER_SN_LEN},
#endif
#ifdef WRITE_WSC_PIN_SUPPORT
	{ GET_WSC_PIN,	"WSC_PIN",	RESERVE_WSC_PIN,	PER_WSC_PIN_LEN},
	{ SET_WSC_PIN,	"WSC_PIN",	RESERVE_WSC_PIN,	PER_WSC_PIN_LEN},
#endif
#ifdef T_CERT_SUPPORT
        { GET_T_CERT,	"T_CERT",	RESERVE_T_CERT,		PER_T_CERT_LEN},
        { SET_T_CERT,	"T_CERT",	RESERVE_T_CERT,		PER_T_CERT_LEN},
#endif
#ifdef DUAL_IMAGE_SUPPORT
        { GET_STABLE,	"STABLE",	RESERVE_STABLE,		PER_STABLE_LEN},
        { SET_STABLE,	"STABLE",	RESERVE_STABLE,		PER_STABLE_LEN},
        { GET_TRY,	"TRY",		RESERVE_TRY,		PER_TRY_LEN},
        { SET_TRY,	"TRY",		RESERVE_TRY,		PER_TRY_LEN},
#endif
#ifdef WRITE_COUNTRY_SUPPORT
	{ GET_COUNTRY,	"COUNTRY",	RESERVE_COUNTRY,        PER_COUNTRY_LEN},
        { SET_COUNTRY,	"COUNTRY",	RESERVE_COUNTRY,        PER_COUNTRY_LEN},
	{ GET_2G_COUNTRY_CODE,	"2G_COUNTRY_CODE",	RESERVE_COUNTRY,        PER_COUNTRY_LEN},
        { SET_2G_COUNTRY_CODE,	"2G_COUNTRY_CODE",	RESERVE_COUNTRY,        PER_COUNTRY_LEN},
	{ GET_5G_COUNTRY_CODE,	"5G_COUNTRY_CODE",	RESERVE_COUNTRY,        PER_COUNTRY_LEN},
        { SET_5G_COUNTRY_CODE,	"5G_COUNTRY_CODE",	RESERVE_COUNTRY,        PER_COUNTRY_LEN},
#endif
#ifdef WRITE_PA_SUPPORT
        { GET_PA2GA0,      "PA2GA0",          RESERVE_PA0,            PER_PA0_LEN},
        { GET_PA2GA0_OLD,  "PA2GA0",          RESERVE_PA0_OLD,        PER_PA0_LEN},
        { SET_PA2GA0,      "PA2GA0",          RESERVE_PA0,            PER_PA0_LEN},
        { GET_PA2GA1,      "PA2GA1",          RESERVE_PA1,            PER_PA1_LEN},
        { GET_PA2GA1_OLD,  "PA2GA1",          RESERVE_PA1_OLD,        PER_PA1_LEN},
        { SET_PA2GA1,      "PA2GA1",          RESERVE_PA1,            PER_PA1_LEN},
        { GET_PA2GA0IDXVAL,"PA2GA0IDXVAL",    RESERVE_PA0IDXVAL,      PER_PA0IDXVAL_LEN},
        { SET_PA2GA0IDXVAL,"PA2GA0IDXVAL",    RESERVE_PA0IDXVAL,      PER_PA0IDXVAL_LEN},
        { GET_PA2GA1IDXVAL,"PA2GA1IDXVAL",    RESERVE_PA1IDXVAL,      PER_PA1IDXVAL_LEN},
        { SET_PA2GA1IDXVAL,"PA2GA1IDXVAL",    RESERVE_PA1IDXVAL,      PER_PA1IDXVAL_LEN},

        { GET_PA5GHA0,      "PA5GHA0",          RESERVE_PA0,            PER_PA0_LEN},
        { GET_PA5GHA0_OLD,  "PA5GHA0",          RESERVE_PA0_OLD,        PER_PA0_LEN},
        { SET_PA5GHA0,      "PA5GHA0",          RESERVE_PA0,            PER_PA0_LEN},
        { GET_PA5GHA1,      "PA5GHA1",          RESERVE_PA1,            PER_PA1_LEN},
        { GET_PA5GHA1_OLD,  "PA5GHA1",          RESERVE_PA1_OLD,        PER_PA1_LEN},
        { SET_PA5GHA1,      "PA5GHA1",          RESERVE_PA1,            PER_PA1_LEN},
        { GET_PA5GHA0IDXVAL,"PA5GHA0IDXVAL",    RESERVE_PA0IDXVAL,      PER_PA0IDXVAL_LEN},
        { SET_PA5GHA0IDXVAL,"PA5GHA0IDXVAL",    RESERVE_PA0IDXVAL,      PER_PA0IDXVAL_LEN},
        { GET_PA5GHA1IDXVAL,"PA5GHA1IDXVAL",    RESERVE_PA1IDXVAL,      PER_PA1IDXVAL_LEN},
        { SET_PA5GHA1IDXVAL,"PA5GHA1IDXVAL",    RESERVE_PA1IDXVAL,      PER_PA1IDXVAL_LEN},
        { GET_PA5GHA2IDXVAL,"PA5GHA2IDXVAL",    RESERVE_PA2IDXVAL,      PER_PA2IDXVAL_LEN},
        { SET_PA5GHA2IDXVAL,"PA5GHA2IDXVAL",    RESERVE_PA2IDXVAL,      PER_PA2IDXVAL_LEN},

        { GET_PA5GLA0,      "PA5GLA0",          RESERVE_PA0,            PER_PA0_LEN},
        { GET_PA5GLA0_OLD,  "PA5GLA0",          RESERVE_PA0_OLD,        PER_PA0_LEN},
        { SET_PA5GLA0,      "PA5GLA0",          RESERVE_PA0,            PER_PA0_LEN},
        { GET_PA5GLA1,      "PA5GLA1",          RESERVE_PA1,            PER_PA1_LEN},
        { GET_PA5GLA1_OLD,  "PA5GLA1",          RESERVE_PA1_OLD,        PER_PA1_LEN},
        { SET_PA5GLA1,      "PA5GLA1",          RESERVE_PA1,            PER_PA1_LEN},
        { GET_PA5GLA0IDXVAL,"PA5GLA0IDXVAL",    RESERVE_PA0IDXVAL,      PER_PA0IDXVAL_LEN},
        { SET_PA5GLA0IDXVAL,"PA5GLA0IDXVAL",    RESERVE_PA0IDXVAL,      PER_PA0IDXVAL_LEN},
        { GET_PA5GLA1IDXVAL,"PA5GLA1IDXVAL",    RESERVE_PA1IDXVAL,      PER_PA1IDXVAL_LEN},
        { SET_PA5GLA1IDXVAL,"PA5GLA1IDXVAL",    RESERVE_PA1IDXVAL,      PER_PA1IDXVAL_LEN},
        { GET_PA5GLA2IDXVAL,"PA5GLA2IDXVAL",    RESERVE_PA2IDXVAL,      PER_PA2IDXVAL_LEN},
        { SET_PA5GLA2IDXVAL,"PA5GLA2IDXVAL",    RESERVE_PA2IDXVAL,      PER_PA2IDXVAL_LEN},

        { GET_PA5GA0,      "PA5GA0",          RESERVE_PA0,            PER_PA0_LEN},
        { GET_PA5GA0_OLD,  "PA5GA0",          RESERVE_PA0_OLD,        PER_PA0_LEN},
        { SET_PA5GA0,      "PA5GA0",          RESERVE_PA0,            PER_PA0_LEN},
        { GET_PA5GA1,      "PA5GA1",          RESERVE_PA1,            PER_PA1_LEN},
        { GET_PA5GA1_OLD,  "PA5GA1",          RESERVE_PA1_OLD,        PER_PA1_LEN},
        { SET_PA5GA1,      "PA5GA1",          RESERVE_PA1,            PER_PA1_LEN},
        { GET_PA5GA0IDXVAL,"PA5GA0IDXVAL",    RESERVE_PA0IDXVAL,      PER_PA0IDXVAL_LEN},
        { SET_PA5GA0IDXVAL,"PA5GA0IDXVAL",    RESERVE_PA0IDXVAL,      PER_PA0IDXVAL_LEN},
        { GET_PA5GA1IDXVAL,"PA5GA1IDXVAL",    RESERVE_PA1IDXVAL,      PER_PA1IDXVAL_LEN},
        { SET_PA5GA1IDXVAL,"PA5GA1IDXVAL",    RESERVE_PA1IDXVAL,      PER_PA1IDXVAL_LEN}, 
	{ GET_PA5GA2IDXVAL,"PA5GA2IDXVAL",    RESERVE_PA2IDXVAL,      PER_PA2IDXVAL_LEN},
	{ SET_PA5GA2IDXVAL,"PA5GA2IDXVAL",    RESERVE_PA2IDXVAL,      PER_PA2IDXVAL_LEN},
#endif

};

struct table *
find_table(int cmd)
{	
	struct table *v = NULL;

	for(v = tables ; v < &tables[sizeof(tables)/sizeof(tables[0])] ; v++) {
		if(v->cmd == cmd)
			return v;
	}
	//return v;
	return 0;
}

int
get_start_address(int cmd)
{
	int start_address = 0;
	
	switch(cmd){
#ifdef WRITE_MAC_SUPPORT
		case GET_MAC:
		case SET_MAC:
			if(!strncmp(nvram_safe_get("pmon_ver"), "PMON", 4))
				start_address = PMON_MAC_START_ADDRESS;
			else
				start_address = CFE_MAC_START_ADDRESS;

			break;
#endif
#ifdef EOU_SUPPORT
		case GET_EOU:
		case SET_EOU:
			start_address = CFE_EOU_KEY_START_ADDRESS;
			break;
#endif
#ifdef WRITE_SN_SUPPORT
		case GET_SN:
		case SET_SN:
			start_address = CFE_SN_START_ADDRESS;
			break;
#endif
#ifdef WRITE_WSC_PIN_SUPPORT
		case GET_WSC_PIN:
		case SET_WSC_PIN:
			start_address = CFE_WSC_PIN_START_ADDRESS;
			break;
#endif
#ifdef WRITE_PA_SUPPORT
                case GET_PA2GA0:
                case SET_PA2GA0:
                        start_address = CFE_PA2GA0_START_ADDRESS;
                        break;
                case GET_PA2GA0_OLD:
                        start_address = CFE_PA2GA0_START_ADDRESS_OLD;
                        break;
                case GET_PA2GA1:
                case SET_PA2GA1:
                        start_address = CFE_PA2GA1_START_ADDRESS;
                        break;
                case GET_PA2GA1_OLD:
                        start_address = CFE_PA2GA1_START_ADDRESS_OLD;
                        break;
                case GET_PA2GA0IDXVAL:
                case SET_PA2GA0IDXVAL:
                        start_address = CFE_PA2GA0IDXVAL_START_ADDRESS;
                        break;
                case GET_PA2GA1IDXVAL:
                case SET_PA2GA1IDXVAL:
                        start_address = CFE_PA2GA1IDXVAL_START_ADDRESS;
                        break;

                case GET_PA5GHA0:
                case SET_PA5GHA0:
                        start_address = CFE_PA5GHA0_START_ADDRESS;
                        break;
                case GET_PA5GHA0_OLD:
                        start_address = CFE_PA5GHA0_START_ADDRESS_OLD;
                        break;
                case GET_PA5GHA1:
                case SET_PA5GHA1:
                        start_address = CFE_PA5GHA1_START_ADDRESS;
                        break;
                case GET_PA5GHA1_OLD:
                        start_address = CFE_PA5GHA1_START_ADDRESS_OLD;
                        break;
                case GET_PA5GHA0IDXVAL:
                case SET_PA5GHA0IDXVAL:
                        start_address = CFE_PA5GHA0IDXVAL_START_ADDRESS;
                        break;
                case GET_PA5GHA1IDXVAL:
                case SET_PA5GHA1IDXVAL:
                        start_address = CFE_PA5GHA1IDXVAL_START_ADDRESS;
                        break;
                case GET_PA5GHA2IDXVAL:
                case SET_PA5GHA2IDXVAL:
                        start_address = CFE_PA5GHA2IDXVAL_START_ADDRESS;
                        break;

                case GET_PA5GLA0:
                case SET_PA5GLA0:
                        start_address = CFE_PA5GLA0_START_ADDRESS;
                        break;
                case GET_PA5GLA0_OLD:
                        start_address = CFE_PA5GLA0_START_ADDRESS_OLD;
                        break;
                case GET_PA5GLA1:
                case SET_PA5GLA1:
                        start_address = CFE_PA5GLA1_START_ADDRESS;
                        break;
                case GET_PA5GLA1_OLD:
                        start_address = CFE_PA5GLA1_START_ADDRESS_OLD;
                        break;
                case GET_PA5GLA0IDXVAL:
                case SET_PA5GLA0IDXVAL:
                        start_address = CFE_PA5GLA0IDXVAL_START_ADDRESS;
                        break;
                case GET_PA5GLA1IDXVAL:
                case SET_PA5GLA1IDXVAL:
                        start_address = CFE_PA5GLA1IDXVAL_START_ADDRESS;
                        break;
                case GET_PA5GLA2IDXVAL:
                case SET_PA5GLA2IDXVAL:
                        start_address = CFE_PA5GLA2IDXVAL_START_ADDRESS;
                        break;

                case GET_PA5GA0:
                case SET_PA5GA0:
                        start_address = CFE_PA5GA0_START_ADDRESS;
                        break;
                case GET_PA5GA0_OLD:
                        start_address = CFE_PA5GA0_START_ADDRESS_OLD;
                        break;
                case GET_PA5GA1:
                case SET_PA5GA1:
                        start_address = CFE_PA5GA1_START_ADDRESS;
                        break;
                case GET_PA5GA1_OLD:
                        start_address = CFE_PA5GA1_START_ADDRESS_OLD;
                        break;
                case GET_PA5GA0IDXVAL:
                case SET_PA5GA0IDXVAL:
                        start_address = CFE_PA5GA0IDXVAL_START_ADDRESS;
                        break;
                case GET_PA5GA1IDXVAL:
                case SET_PA5GA1IDXVAL:
                        start_address = CFE_PA5GA1IDXVAL_START_ADDRESS;
                        break; 
                case GET_PA5GA2IDXVAL:
                case SET_PA5GA2IDXVAL:
                        start_address = CFE_PA5GA2IDXVAL_START_ADDRESS;
                        break;

#endif
#ifdef T_CERT_SUPPORT
		case GET_T_CERT:
		case SET_T_CERT:
			start_address = CFE_T_CERT_START_ADDRESS;
			break;
#endif
#ifdef DUAL_IMAGE_SUPPORT
		case GET_STABLE:
		case SET_STABLE:
			if(nvram_match("boot_from", "1")) {
				start_address = image1_stable_loc + 22;
				printk("start_address 1=[%x]\n", start_address);
			}	
			else {
				start_address = image2_stable_loc + 22;
				printk("start_address 2=[%x]\n", start_address);
			}
			break;
		case GET_TRY:
		case SET_TRY:
			if(nvram_match("boot_from", "1"))
				start_address = image1_stable_loc + 24;
			else
				start_address = image2_stable_loc + 24;
			break;
		default:
			printk("Invalid cmd [%d]\n", cmd);
			return -1;
#endif
#ifdef WRITE_COUNTRY_SUPPORT
		case GET_COUNTRY:
		case SET_COUNTRY:
			start_address = CFE_COUNTRY_START_ADDRESS;
			break;
		case GET_2G_COUNTRY_CODE:
		case SET_2G_COUNTRY_CODE:
			start_address = CFE_2G_COUNTRY_CODE_START_ADDRESS;
			break;
		case GET_5G_COUNTRY_CODE:
		case SET_5G_COUNTRY_CODE:
			start_address = CFE_5G_COUNTRY_CODE_START_ADDRESS;
			break;
#endif
	}

	return start_address;
}


int
data_init(MYDATA *mydatas, struct table *v)
{
	int start_address = get_start_address(v->cmd);
	unsigned char *base = (unsigned char *) (FLASH_BASE + start_address);
	int i;
	//unsigned char blank[] = {[0 ... 2300] = 0xFF};
	unsigned char *blank;

	char *ptr = (char *) mydatas;
	char *start = (char *) mydatas;

	printk("%s(): base = 0x%x\n", __FUNCTION__, (int) base);
	if(start_address < 0) {
		return ERR;
	}

	//blank = (char *)vmalloc(sizeof(MYDATA));
	blank = (char *)kmalloc(sizeof(MYDATA), GFP_ATOMIC);
	memset(blank, 0xFF, sizeof(MYDATA));

	ptr = ptr + sizeof(int);
	memcpy(ptr, base , v->count * v->len);

	for(i=0 ; i<v->count ; i++) {
		if(!memcmp(ptr, blank, v->len))
			break;
		ptr = ptr + v->len;
	}	
	
	*start = i;

	printk("%s(): location = [%d], mydatas index = %d\n", __FUNCTION__, i, mydatas->mac.index);
	
	//vfree(blank);
	kfree(blank);
	return i;
}

/* Local vars */
static si_t *sih = NULL;
static chipcregs_t *cc = NULL;

int
set_data(char *string, int index, struct table *v)
{
	int ret = 0,bytes;

	unsigned long avail_addr = -1;
	char nvmsg[40];
	int flash_not_exist;
	int string_len;
	int start_address;

	struct sflash *sflash;
	osl_t *osh;
	uint32 fltype = PFLASH;

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

	

#ifdef T_CERT_SUPPORT
	if (!strcmp(v->desc, "T_CERT")){
		string_len = strlen(string + 12) + 12;
	}
	else
#endif
		string_len = strlen(string);

	DEBUGP("%s(): init\n", __FUNCTION__);

	start_address = get_start_address(v->cmd);

	if(start_address < 0) 
		return ERR;

	avail_addr = (unsigned long)(index * v->len  + start_address);

	printk("%s(): The location %d is available, address is 0x%lX!\n", __FUNCTION__, index, avail_addr);
	printk("%s(): Start writing string... strlen(string)=[%d]\n", __FUNCTION__, string_len);

#ifdef WRITE_WSC_PIN_SUPPORT
	if(v->cmd != SET_WSC_PIN) //For E3200: Add '\0' in SET cmd and only skip write WPS PIN. 
#endif
	{
		string_len += 1;  //include '\0'
	}

	if (fltype == SFLASH_ST || fltype == SFLASH_AT) {
		printk("%s(): This Flash type is serial!\n", __FUNCTION__);
		sflash = sflash_init(sih, cc);
		while (string_len) {
			if ((bytes = sflash_write(sih, cc, (uint)avail_addr, (uint) string_len, string)) < 0) {
				ret = bytes;
				break;
			}
			while (sflash_poll(sih, cc, (uint) avail_addr));
			avail_addr += (uint) bytes;
			string_len -= (uint) bytes;
			string += bytes;
			//ret = sflash_write(sih, cc, (uint)avail_addr, (uint) string_len, string);
	       }
	}
	else {
		printk("%s(): This Flash type is Parallel!\n", __FUNCTION__);
		flash_not_exist = flash_init((void*)FLASH_BASE, nvmsg);
		ret = flash_write(avail_addr, (uint16*) string, (uint) string_len);
	}
	DEBUGP("%s(): Write done (%d)\n", __FUNCTION__, ret);

	return ret;
}

int ctmisc_ioctl(struct inode * inode, struct file *flip, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	//char string[2300];
	char *string;
	int index;
	struct table *v;
	static u8 value;
	char nvmsg[254];

	MYDATA mydatas;
	//string = (char *)vmalloc(sizeof(MYDATA));
	string = (char *)kmalloc(sizeof(MYDATA), GFP_ATOMIC);

	memset(string, 0, sizeof(MYDATA));
	memset(&mydatas, 0, sizeof(mydatas));

	printk("%s: cmd=0x%02x, buffer size=%d\n", __FUNCTION__, cmd, sizeof(MYDATA));

	switch(cmd)
	{
#ifdef WRITE_MAC_SUPPORT
		case GET_MAC:
#endif
#ifdef EOU_SUPPORT
		case GET_EOU:
#endif
#ifdef WRITE_SN_SUPPORT
		case GET_SN:
#endif
#ifdef WRITE_WSC_PIN_SUPPORT
		case GET_WSC_PIN:
#endif
#ifdef WRITE_PA_SUPPORT
                case GET_PA2GA0:
                case GET_PA2GA1:
                case GET_PA2GA0_OLD:
                case GET_PA2GA1_OLD:
                case GET_PA2GA0IDXVAL:
                case GET_PA2GA1IDXVAL:
                case GET_PA5GHA0:
                case GET_PA5GHA1:
                case GET_PA5GHA0_OLD:
                case GET_PA5GHA1_OLD:
                case GET_PA5GHA0IDXVAL:
                case GET_PA5GHA1IDXVAL:
                case GET_PA5GHA2IDXVAL:
                case GET_PA5GLA0:
                case GET_PA5GLA1:
                case GET_PA5GLA0_OLD:
                case GET_PA5GLA1_OLD:
                case GET_PA5GLA0IDXVAL:
                case GET_PA5GLA1IDXVAL:
                case GET_PA5GLA2IDXVAL:
                case GET_PA5GA0:
                case GET_PA5GA1:
                case GET_PA5GA0_OLD:
                case GET_PA5GA1_OLD:
                case GET_PA5GA0IDXVAL:
                case GET_PA5GA1IDXVAL:
                case GET_PA5GA2IDXVAL:
#endif
#ifdef T_CERT_SUPPORT
		case GET_T_CERT:
#endif
#ifdef DUAL_IMAGE_SUPPORT
		case GET_STABLE:
		case GET_TRY:
#endif
#ifdef WRITE_COUNTRY_SUPPORT
		case GET_COUNTRY:
		case GET_2G_COUNTRY_CODE:
		case GET_5G_COUNTRY_CODE:
#endif
			v = find_table(cmd);

			if(!v) {
				printk("Cann't find %d command in table\n", cmd);
				return 0;
			}
			
			ret = data_init(&mydatas, v);
			printk("%s: index=%d \n", __FUNCTION__, ret);

			if(ret < 0)
				break;

			if (copy_to_user((void *) arg, &mydatas, sizeof(mydatas)))
				break;

			ret = 0;
                        break;

#ifdef WRITE_MAC_SUPPORT
		case SET_MAC:
#endif
#ifdef EOU_SUPPORT
		case SET_EOU:
#endif
#ifdef WRITE_SN_SUPPORT
		case SET_SN:
#endif
#ifdef WRITE_PA_SUPPORT
                case SET_PA2GA0:
                case SET_PA2GA1:
                case SET_PA2GA0IDXVAL:
                case SET_PA2GA1IDXVAL:
                case SET_PA5GHA0:
                case SET_PA5GHA1:
                case SET_PA5GHA0IDXVAL:
                case SET_PA5GHA1IDXVAL:
                case SET_PA5GHA2IDXVAL:
                case SET_PA5GLA0:
                case SET_PA5GLA1:
                case SET_PA5GLA0IDXVAL:
                case SET_PA5GLA1IDXVAL:
                case SET_PA5GLA2IDXVAL:
                case SET_PA5GA0:
                case SET_PA5GA1:
                case SET_PA5GA0IDXVAL:
                case SET_PA5GA1IDXVAL:
                case SET_PA5GA2IDXVAL:
#endif
#ifdef T_CERT_SUPPORT
		case SET_T_CERT:
#endif
#ifdef WRITE_WSC_PIN_SUPPORT
		case SET_WSC_PIN:
#endif
#ifdef DUAL_IMAGE_SUPPORT
		case SET_STABLE:
		case SET_TRY:
#endif
#ifdef WRITE_COUNTRY_SUPPORT
		case SET_COUNTRY:
		case SET_2G_COUNTRY_CODE:
		case SET_5G_COUNTRY_CODE:
#endif
			v = find_table(cmd);
			int noncopylen=0;
			if (noncopylen = copy_from_user(string,(void *) arg, v->len)) {
				printk("%s(): Get %s error, error code = %d, len = %d \n", __FUNCTION__, v->desc,noncopylen, v->len);
				break;
			}
			//printk("%s(): Get %s = [%s]\n", __FUNCTION__, v->desc, string);
			printk("%s(): Get %s\n", __FUNCTION__, v->desc);
			index = data_init(&mydatas, v);

			if(index == v->count ) {
	                        printk("%s(): The %s space is full! Please update boot.bin\n", __FUNCTION__, v->desc);
       	         	        ret = FULL;
       		        }
			else if (!strlen(string)) {
				ret = ERR;
			}
			else {
				ret = set_data(string, index, v);	
				printk("%s: ret=%d\n", __FUNCTION__, ret);
				/*if(ret == 0)*/
				if (ret >= 0)
					ret = index;
				else
					ret = ERR;
			}

			//if (put_user(ret, (int *) arg))
			if (copy_to_user((int *) arg, &ret, sizeof(int)))
				break;
			break;

		case GET_FLASH_TYPE:
			memset(&nvmsg, 0, sizeof(nvmsg));
			flash_init((void*)FLASH_BASE, nvmsg);
			printk("Flash Type: %s\n", nvmsg);
			if (copy_to_user((void *) arg, &nvmsg, sizeof(nvmsg)))
	                        break;

			ret = 0;
			break;

	/* Below is for 4704 external IO led */
		case GOT_IP:
			value = (value & INTERNET_LED) | ILED_SOLID_GREEN;
			*(volatile u8*)(KSEG1ADDR(EXTERNAL_IF_BASE)+ASYNC_IF_BASE)=value; // tallest
			//printk("tallest:=====( DATA=0x%x  cmd=0x%x )=====\n",*(volatile u8*)(KSEG1ADDR(EXTERNAL_IF_BASE)+ASYNC_IF_BASE),cmd);
			break;

		case RELEASE_IP:
			value = (value & INTERNET_LED) | ILED_OFF;
			*(volatile u8*)(KSEG1ADDR(EXTERNAL_IF_BASE)+ASYNC_IF_BASE)=value; // tallest
			//printk("tallest:=====( DATA=0x%x  cmd=0x%x )=====\n",*(volatile u8*)(KSEG1ADDR(EXTERNAL_IF_BASE)+ASYNC_IF_BASE),cmd);
			break;

		case GET_IP_ERROR:
			value = (value & INTERNET_LED) | ILED_SOLID_AMBER;
			*(volatile u8*)(KSEG1ADDR(EXTERNAL_IF_BASE)+ASYNC_IF_BASE)=value; // tallest
			//printk("tallest:=====( DATA=0x%x  cmd=0x%x )=====\n",*(volatile u8*)(KSEG1ADDR(EXTERNAL_IF_BASE)+ASYNC_IF_BASE),cmd);
			break;

		case RELEASE_WAN_CONTROL:
			value = (value & WAN_LED) | WLED_FLASHING_GREEN;
			*(volatile u8*)(KSEG1ADDR(EXTERNAL_IF_BASE)+ASYNC_IF_BASE)=value; // tallest
			//printk("tallest:=====( DATA=0x%x  cmd=0x%x )=====\n",*(volatile u8*)(KSEG1ADDR(EXTERNAL_IF_BASE)+ASYNC_IF_BASE),cmd);
			break;
		case USB_DATA_ACCESS:
			value = (value & USB_PORT1_LED) | USB_LED1_BLINKING;
			*(volatile u8*)(KSEG1ADDR(EXTERNAL_IF_BASE)+ASYNC_IF_BASE)=value; // tallest
			//printk("tallest:=====( DATA=0x%x  cmd=0x%x )=====\n",*(volatile u8*)(KSEG1ADDR(EXTERNAL_IF_BASE)+ASYNC_IF_BASE),cmd);
			break;

		case USB_CONNECT:
			value = (value & USB_PORT1_LED) | USB_LED1_ON;
			*(volatile u8*)(KSEG1ADDR(EXTERNAL_IF_BASE)+ASYNC_IF_BASE)=value; // tallest
			//printk("tallest:=====( DATA=0x%x  cmd=0x%x )=====\n",*(volatile u8*)(KSEG1ADDR(EXTERNAL_IF_BASE)+ASYNC_IF_BASE),cmd);
			break;

		case USB_DISCONNECT:
			value = (value & USB_PORT1_LED) | USB_LED1_OFF;
			*(volatile u8*)(KSEG1ADDR(EXTERNAL_IF_BASE)+ASYNC_IF_BASE)=value; // tallest
			//printk("tallest:=====( DATA=0x%x  cmd=0x%x )=====\n",*(volatile u8*)(KSEG1ADDR(EXTERNAL_IF_BASE)+ASYNC_IF_BASE),cmd);
			break;
		default:
			printk("Invalid cmd [0x%x]\n", cmd);
			ret = -1;
			break;
	}

	//vfree(string);
	kfree(string);
	printk("tallest:=====(ctmisc ioctl done...)=====\n");
	return ret;
}

struct file_operations ctmisc_fops = {
	read: ctmisc_read,
	write: ctmisc_write,
	open: ctmisc_open, 
	release: ctmisc_release,
	ioctl: ctmisc_ioctl,
	flush: ctmisc_flush,
};

//#define CTMISC_MAJOR	250
//#define CTMISC_MINOR	0
#define CTMISC_MAJOR	MISC_MAJOR /* attach it to misc device */
#define CTMISC_MINOR	MISC_DYNAMIC_MINOR /* dynamic minor by default */

static struct miscdevice ctmisc_dev = {
        .minor  = CTMISC_MINOR,
        .name   = "ctmisc",
        .fops   = &ctmisc_fops,
};

int init_module(void)
{
	int ret;	

#if 0
	if((ret = devfs_register_chrdev(CTMISC_MAJOR, "ctmisc", &ctmisc_fops))) {
                printk(KERN_ERR "failed to register MISC device (%d)\n", ret);
		return ret;
	}

	ctmisc_handle = devfs_register(NULL, "ctmisc", DEVFS_FL_DEFAULT, 
				     CTMISC_MAJOR, CTMISC_MINOR, 
				     S_IFCHR | S_IRUGO | S_IWUGO, 
				     &ctmisc_fops, NULL);

#else
        if((ret = misc_register(&ctmisc_dev))) {
                printk(KERN_ERR "failed to register MISC device (%d)\n", ret);
                return ret;
        }
#endif
#if 0
        if(nvram_match("boardtype", "0x04cf"))
                flash_data_width = sizeof(uint8);
        else
                flash_data_width = sizeof(uint16);
#endif

	printk("Register /dev/ctmisc device, major:%d minor:%d\n", CTMISC_MAJOR, CTMISC_MINOR);

	return 0;
}

void cleanup_module(void)
{
	printk("Unregister /dev/ctmisc device\n");

#if 0
	devfs_unregister(ctmisc_handle);

	devfs_unregister_chrdev(0, "ctmisc");
#else
	misc_deregister(&ctmisc_dev);
#endif
}

