/*
 * Copyright (C) 2009, CyberTAN Corporation
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND CYBERTAN GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. CYBERTAN
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 */

#include <code_pattern.h>
#include <cy_conf.h>

#define RESERVE_MAC	8
#define PER_MAC_LEN	18      // contain '\0'

#define RESERVE_EOU_KEY	5
#define PER_EOU_KEY_LEN	522	// 8+256+258

#define RESERVE_SN	8
#define PER_SN_LEN	20

#define RESERVE_PA0_OLD 8
#define RESERVE_PA0     8
#define PER_PA0_LEN     4

#define RESERVE_PA1_OLD 8
#define RESERVE_PA1     8
#define PER_PA1_LEN     4

#define RESERVE_PA0IDXVAL	8
#define PER_PA0IDXVAL_LEN	24
#define RESERVE_PA1IDXVAL	8
#define PER_PA1IDXVAL_LEN	24
//Jemmy add for save 5G antx2 PA value
#define RESERVE_PA2IDXVAL	8
#define PER_PA2IDXVAL_LEN	24

#define RESERVE_COUNTRY	1	// for release, we just use 1 country_code
#define PER_COUNTRY_LEN	16

#define RESERVE_WSC_PIN 8
#define PER_WSC_PIN_LEN 8

#define RESERVE_T_CERT      2
#define PER_T_CERT_LEN      2816

#define RESERVE_STABLE      1 
#define PER_STABLE_LEN      2

#define RESERVE_TRY	3
#define PER_TRY_LEN	2

#define PMON_MAC_START_ADDRESS	0x2000
#define PMON_VER_START_ADDRESS	0x2100

#define CFE_MAC_START_ADDRESS	0x3EF00
#define CFE_VER_START_ADDRESS	0x1FF8

#define CFE_PA5GHA2IDXVAL_START_ADDRESS	0x3F980 // 256K-2K-512-8*4-8*4-8*4-8*4-8*24-8*24
#define CFE_PA5GLA2IDXVAL_START_ADDRESS	0x3F8c0 // 256K-2K-512*2-8*4-8*4-8*4-8*4-8*24-8*24
#define CFE_PA5GA2IDXVAL_START_ADDRESS	0x3F800 // 256K-2K-512*3-8*4-8*4-8*4-8*4-8*24-8*24

#define CFE_PA2GA0_START_ADDRESS_OLD	0x3F7E0 // 256K-2K-8*4
#define CFE_PA2GA1_START_ADDRESS_OLD	0x3F7C0 // 256K-2K-8*4-8*4
#define CFE_PA2GA0_START_ADDRESS	0x3F7A0 // 256K-2K-8*4-8*4-8*4
#define CFE_PA2GA1_START_ADDRESS	0x3F780 // 256K-2K-8*4-8*4-8*4-8*4
#define CFE_PA2GA0IDXVAL_START_ADDRESS	0x3F6C0 // 256K-2K-8*4-8*4-8*4-8*4-8*24
#define CFE_PA2GA1IDXVAL_START_ADDRESS	0x3F600 // 256K-2K-8*4-8*4-8*4-8*4-8*24-8*24

#define CFE_PA5GHA0_START_ADDRESS_OLD	0x3F5E0 // 256K-2K-512-8*4
#define CFE_PA5GHA1_START_ADDRESS_OLD	0x3F5C0 // 256K-2K-512-8*4-8*4
#define CFE_PA5GHA0_START_ADDRESS	0x3F5A0 // 256K-2K-512-8*4-8*4-8*4
#define CFE_PA5GHA1_START_ADDRESS	0x3F580 // 256K-2K-512-8*4-8*4-8*4-8*4
#define CFE_PA5GHA0IDXVAL_START_ADDRESS	0x3F4C0 // 256K-2K-512-8*4-8*4-8*4-8*4-8*24
#define CFE_PA5GHA1IDXVAL_START_ADDRESS	0x3F400 // 256K-2K-512-8*4-8*4-8*4-8*4-8*24-8*24

#define CFE_PA5GLA0_START_ADDRESS_OLD	0x3F3E0 // 256K-2K-512*2-8*4
#define CFE_PA5GLA1_START_ADDRESS_OLD	0x3F3C0 // 256K-2K-512*2-8*4-8*4
#define CFE_PA5GLA0_START_ADDRESS	0x3F3A0 // 256K-2K-512*2-8*4-8*4-8*4
#define CFE_PA5GLA1_START_ADDRESS	0x3F380 // 256K-2K-512*2-8*4-8*4-8*4-8*4
#define CFE_PA5GLA0IDXVAL_START_ADDRESS	0x3F2C0 // 256K-2K-512*2-8*4-8*4-8*4-8*4-8*24
#define CFE_PA5GLA1IDXVAL_START_ADDRESS	0x3F200 // 256K-2K-512*2-8*4-8*4-8*4-8*4-8*24-8*24

#define CFE_PA5GA0_START_ADDRESS_OLD	0x3F1E0 // 256K-2K-512*3-8*4
#define CFE_PA5GA1_START_ADDRESS_OLD	0x3F1C0 // 256K-2K-512*3-8*4-8*4
#define CFE_PA5GA0_START_ADDRESS	0x3F1A0 // 256K-2K-512*3-8*4-8*4-8*4
#define CFE_PA5GA1_START_ADDRESS	0x3F180 // 256K-2K-512*3-8*4-8*4-8*4-8*4
#define CFE_PA5GA0IDXVAL_START_ADDRESS	0x3F0C0 // 256K-2K-512*3-8*4-8*4-8*4-8*4-8*24
#define CFE_PA5GA1IDXVAL_START_ADDRESS	0x3F000 // 256K-2K-512*3-8*4-8*4-8*4-8*4-8*24-8*24

/* never use EOU !!! */
/* CFE_SN_START_ADDRESS - CFE_EOU_KEY_START_ADDRESS < RESERVE_EOU_KEY * PER_EOU_KEY_LEN */
/* it will damage SN if you write EOU KEY */
#define CFE_WSC_PIN_START_ADDRESS	0x3FCDC	// 256K-2K !! Use the same location with EOU KEY !!
//#define CFE_SN_START_ADDRESS		0x3FE32      // 256K-3K+(522*5)
#define CFE_SN_START_ADDRESS		0x3FE30      // 256K-3K+(522*5) round 4 bytes
/* since we use WPS instead of EOU, */
/* and WPS reserve space is RESERVE_WSC_PIN * PER_WSC_PIN_LEN = 8*8 = 64, */
/* it should be OK, if CFE_COUNTRY_START_ADDRESS - CFE_WSC_PIN_START_ADDRESS > 64 */
#define CFE_COUNTRY_START_ADDRESS	CFE_SN_START_ADDRESS - (RESERVE_COUNTRY * PER_COUNTRY_LEN)
#define CFE_2G_COUNTRY_CODE_START_ADDRESS	CFE_COUNTRY_START_ADDRESS - (RESERVE_COUNTRY * PER_COUNTRY_LEN)
#define CFE_5G_COUNTRY_CODE_START_ADDRESS	CFE_2G_COUNTRY_CODE_START_ADDRESS - (RESERVE_COUNTRY * PER_COUNTRY_LEN)

/* don't use T-mobile CERT with PA write together !!! */

#define GET_MAC	0x11
#define SET_MAC	0x12


#define GET_SN	0x15
#define SET_SN	0x16



#define GET_FLASH_TYPE 0x17

#define GET_PA2GA0         0x20
#define GET_PA2GA1         0x21
#define SET_PA2GA0         0x22
#define SET_PA2GA1         0x23
#define GET_PA2GA0_OLD     0x24
#define GET_PA2GA1_OLD     0x25
#define GET_PA2GA0IDXVAL   0x28
#define SET_PA2GA0IDXVAL   0x29
#define GET_PA2GA1IDXVAL   0x2a
#define SET_PA2GA1IDXVAL   0x2b

#define GET_PA5GHA0         0x30
#define GET_PA5GHA1         0x31
#define SET_PA5GHA0         0x32
#define SET_PA5GHA1         0x33
#define GET_PA5GHA0_OLD     0x34
#define GET_PA5GHA1_OLD     0x35
#define GET_PA5GHA0IDXVAL   0x38
#define SET_PA5GHA0IDXVAL   0x39
#define GET_PA5GHA1IDXVAL   0x3a
#define SET_PA5GHA1IDXVAL   0x3b
#define GET_PA5GHA2IDXVAL   0x3c
#define SET_PA5GHA2IDXVAL   0x3d

#define GET_PA5GLA0         0x40
#define GET_PA5GLA1         0x41
#define SET_PA5GLA0         0x42
#define SET_PA5GLA1         0x43
#define GET_PA5GLA0_OLD     0x44
#define GET_PA5GLA1_OLD     0x45
#define GET_PA5GLA0IDXVAL   0x48
#define SET_PA5GLA0IDXVAL   0x49
#define GET_PA5GLA1IDXVAL   0x4a
#define SET_PA5GLA1IDXVAL   0x4b
#define GET_PA5GLA2IDXVAL   0x4c
#define SET_PA5GLA2IDXVAL   0x4d

#define GET_PA5GA0         0x50
#define GET_PA5GA1         0x51
#define SET_PA5GA0         0x52
#define SET_PA5GA1         0x53
#define GET_PA5GA0_OLD     0x54
#define GET_PA5GA1_OLD     0x55
#define GET_PA5GA0IDXVAL   0x58
#define SET_PA5GA0IDXVAL   0x59
#define GET_PA5GA1IDXVAL   0x5a
#define SET_PA5GA1IDXVAL   0x5b
#define GET_PA5GA2IDXVAL   0x5c
#define SET_PA5GA2IDXVAL   0x5d

#define GET_WSC_PIN	0x26
#define SET_WSC_PIN	0x27

#define GET_COUNTRY	0x2c
#define SET_COUNTRY	0x2d
#define GET_2G_COUNTRY_CODE	0x2e
#define SET_2G_COUNTRY_CODE	0x2f
#define GET_5G_COUNTRY_CODE	0x5e
#define SET_5G_COUNTRY_CODE	0x5f

#define FULL	-1
#define	ILLEGAL	-2
#define ERR	-3


#define NOT_NULL(var,m,c) ( \
        var[m] != c && var[m+1] != c && var[m+2] != c && var[m+3] != c && var[m+4] != c && var[m+5] != c \
)

#define IS_NULL(var,m,c) ( \
        var[m] == c && var[m+1] == c && var[m+2] == c && var[m+3] == c && var[m+4] == c && var[m+5] == c \
)

static INLINE int
IS_CNULL(unsigned char *var, int m, unsigned char c, int len) {
        int i;
        for(i=0 ; i<len ; i++) {
                if( var[m+i] != c )
                        return 0;
        }
        return 1;
}

static INLINE int
NOT_CNULL(unsigned char *var, int m, unsigned char c, int len) {
        int i;
        for(i=0 ; i<len ; i++) {
                if( var[m+i] != c )
			return 1;
        }
        return 0;
}

#define MAC_ADD(mac) ({\
                int i,j; \
                unsigned char m[6]; \
                /* sscanf(mac,"%x:%x:%x:%x:%x:%x",&m[0],&m[1],&m[2],&m[3],&m[4],&m[5]);   will error */ \
                for(j=0,i=0 ; i<PER_MAC_LEN ; i+=3,j++) { \
                        if(mac[i] >= 'A' && mac[i] <= 'F')              mac[i] = mac[i] - 55;\
                        if(mac[i+1] >= 'A' && mac[i+1] <= 'F')  mac[i+1] = mac[i+1] - 55;\
                        if(mac[i] >= 'a' && mac[i] <= 'f')              mac[i] = mac[i] - 87;\
                        if(mac[i+1] >= 'a' && mac[i+1] <= 'f')  mac[i+1] = mac[i+1] - 87;\
                        if(mac[i] >= '0' && mac[i] <= '9')              mac[i] = mac[i] - 48;\
                        if(mac[i+1] >= '0' && mac[i+1] <= '9')  mac[i+1] = mac[i+1] - 48;\
                        m[j] = mac[i]*16 + mac[i+1]; \
                } \
                for(i=5 ; i>=3 ; i--){ \
                        if( m[i] == 0xFF)       { m[i] = 0x0; continue; } \
                        else                    { m[i] = m[i] + 1; break; } \
                } \
                sprintf(mac,"%02X:%02X:%02X:%02X:%02X:%02X",m[0],m[1],m[2],m[3],m[4],m[5]); \
})

