#include "code_pattern.h"

#if LINKSYS_MODEL == E300
  #if LOCALE == USA
    #define CYBERTAN_VERSION	"v1.0.02"
    #define SERIAL_NUMBER	"04"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #else	// ETSI
    #define CYBERTAN_VERSION	"v0.00.01"
    #define SERIAL_NUMBER	"09"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #endif
#elif LINKSYS_MODEL == E30X
  #if LOCALE == USA
    #define CYBERTAN_VERSION	"v1.0.00"
    #define SERIAL_NUMBER	"01"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #else	// ETSI
    #define CYBERTAN_VERSION	"v1.0.00"
    #define SERIAL_NUMBER	"01"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #endif
#elif LINKSYS_MODEL == E1550
  #if LOCALE == USA
    #define CYBERTAN_VERSION	"v0.1"
    #define SERIAL_NUMBER	"01"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #else	// ETSI
    #define CYBERTAN_VERSION	"v1.0.01"
    #define SERIAL_NUMBER	"01"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #endif
#elif LINKSYS_MODEL == E155X
  #if LOCALE == USA
    #define CYBERTAN_VERSION	"v1.0.02"
    #define SERIAL_NUMBER	"01"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #else	// ETSI
    #define CYBERTAN_VERSION	"v1.0.01"
    #define SERIAL_NUMBER	"02"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #endif
#elif LINKSYS_MODEL == E2500
  #if LOCALE == USA
    #define CYBERTAN_VERSION	"v1.0.00"
    #define SERIAL_NUMBER	"01"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #else	// ETSI
    #define CYBERTAN_VERSION	"v1.0.00"
    #define SERIAL_NUMBER	"01"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #endif
#elif LINKSYS_MODEL == E250X
  #if LOCALE == USA
    #define CYBERTAN_VERSION	"v1.0.00"
    #define SERIAL_NUMBER	"01"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #else	// ETSI
    #define CYBERTAN_VERSION	"v1.0.00"
    #define SERIAL_NUMBER	"01"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #endif
#elif LINKSYS_MODEL == E3200
  #if LOCALE == USA
    #define CYBERTAN_VERSION	"v1.0.03"
    #define SERIAL_NUMBER	"2"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    ""
  #else	// ETSI
    #define CYBERTAN_VERSION	"v1.0.00"
    #define SERIAL_NUMBER	"01"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #endif
#elif LINKSYS_MODEL == E4200
  #if LOCALE == USA
    #define CYBERTAN_VERSION	"v1.0.00"
    #define SERIAL_NUMBER	"01"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #else	// ETSI
    #define CYBERTAN_VERSION	"v1.0.00"
    #define SERIAL_NUMBER	"01"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #endif
#elif LINKSYS_MODEL == E420X
  #if LOCALE == USA
    #define CYBERTAN_VERSION	"v1.0.00"
    #define SERIAL_NUMBER	"01"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #else	// ETSI
    #define CYBERTAN_VERSION	"v1.0.00"
    #define SERIAL_NUMBER	"01"
    #define MINOR_VERSION	""
    #define BUILD_KEYWORD   " B"
    #define BUILD_NUMBER    SERIAL_NUMBER
    #define BETA_VERSION    " "
  #endif
#else
#error "Unknown model, can not set CYBERTAN_VERSION"
#endif

#if LINKSYS_MODEL == T_MOBILE
    #define CFES_BOOT_VERSION	"v5.3"
#else
    #define CFES_BOOT_VERSION	"v4.2"
#endif

#define LANG_VERSION		"v1.00.00"    //for lang.bin version control(setupwizard)
#define PMON_BOOT_VERSION	"v1.8"

#if LINKSYS_MODEL == T_MOBILE
#define BOOT_IPADDR "192.168.0.1"
#define BOOT_NETMASK "255.255.255.0"
#else
#define BOOT_IPADDR "192.168.1.1"
#define BOOT_NETMASK "255.255.255.0"
#endif

#define SUPPORT_4712_CHIP	0x0001
#define SUPPORT_INTEL_FLASH	0x0002
#define SUPPORT_5325E_SWITCH	0x0004
#define SUPPORT_4704_CHIP	0x0008
#define SUPPORT_5352E_CHIP	0x0010

struct code_header {
	char magic[4];	// Code Pattern
	char res1[4];	// for extra magic
	char fwdate[3];	// Firmware build date
	char fwvern[3];	// Firmware version
	char id[4];	// U2ND
	char hw_ver;    // 0) for 4702, 1) for 4712, 2) for 4712L, 3) for 4704, 4) for 5352E
	unsigned char  sn;	// Serial Number
	unsigned short flags;
	unsigned char  stable[2];	// The image is stable (for dual image)
	unsigned char  try1[2];		// Try to boot image first time (for dual image)
	unsigned char  try2[2];		// Try to boot image second time (for dual image)
	unsigned char  try3[2];		// Try to boot image third time (for dual_image)
	unsigned char  res3[2];
} ;

//#ifdef MULTILANG_SUPPORT
struct lang_header {
        char magic[4];
        char res1[4];   // for extra magic
        char fwdate[3];
        char fwvern[3];
        char id[4];     // U2ND
        char hw_ver;    // 0: for 4702, 1: for 4712
	char res2;
        unsigned long len;
        unsigned char res3[8];
} ;
//#endif

struct boot_header {
	char magic[3];
	char res[29];
};

/***************************************
 * define upnp misc                    *
 ***************************************/
  #if LANGUAGE == ENGLISH
    #define URL			"http://www.linksys.com/"
  #else
    #define URL			"http://www.linksys.co.jp/"
  #endif
  #define DEV_FRIENDLY_NAME	"Linksys"MODEL_NAME
  #define DEV_MFR		"Cisco"
  //#define DEV_MFR_URL		URL
  #define DEV_MFR_URL		"http://www.linksysbycisco.com"
  #define DEV_MODEL_DESCRIPTION	"Internet Access Server"
  #define DEV_MODEL		MODEL_NAME
  #define DEV_MODEL_NO		CYBERTAN_VERSION
  //#define DEV_MODEL_URL		URL
  #define DEV_MODEL_URL		"http://www.linksysbycisco.com/international"

/***************************************
 * define Parental Control link        *
 ***************************************/
#if LOCALE == EUROPE
  #define	SIGN_UP_URL	"http://pcsvc.ourlinksys.com/eu/language.jsp"
  #define	MORE_INFO_URL	"http://www.linksys.com/pcsvc/eu/info_eu.asp"
  #define	ADMIN_URL	"http://pcsvc.ourlinksys.com/en"
#elif LOCALE == GERMANY
  #define	SIGN_UP_URL	"http://pcsvc.ourlinksys.com/de/trial.asp"
  #define	MORE_INFO_URL	"http://www.linksys.com/pcsvc/de/info_de.asp"
  #define	ADMIN_URL	"http://pcsvc.ourlinksys.com/de/admin.asp"
#elif LOCALE == FRANCE
  #define	SIGN_UP_URL	"http://pcsvc.ourlinksys.com/fr/trial.asp"
  #define	MORE_INFO_URL	"http://www.linksys.com/pcsvc/fr/info_fr.asp"
  #define	ADMIN_URL	"http://pcsvc.ourlinksys.com/fr/admin.asp"
#else
  #define	SIGN_UP_URL	"http://pcsvc.ourlinksys.com/us/trial.asp"
  #define	MORE_INFO_URL	"http://www.linksys.com/pcsvc/info.asp"
  #define	ADMIN_URL	"http://pcsvc.ourlinksys.com/us/admin.asp"
#endif

/***************************************
 * define PPTP info		       * 
 ***************************************/
#define	PPTP_VENDOR	"Linksys"
#define PPTP_HOSTNAME	""

/***************************************
 * define L2TP info		       *
 ***************************************/
#define	L2TP_VENDOR	"Linksys"
#define L2TP_HOSTNAME	MODEL_NAME //2005-03-04 by kanki

