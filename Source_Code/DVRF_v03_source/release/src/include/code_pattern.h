/*
 * Copyright (C) 2010, CyberTAN Corporation
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND CYBERTAN GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. CYBERTAN
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 */
#define CODE_ID		"U2ND"
#define BOOT_PATTERN	"EST"
#define UP_PMON		1
#define UP_MAC		2
#define UP_CODE		3
#define UP_PIGGY	4
#define UP_EOU_KEY	5
#define UP_SN		6
#define UP_LANG		7
#define UP_T_CERT	8
#define CMP_T_CERT	9	//for factory test.
#define UP_CODE2       10
#define UP_FULL_WL     11
#define UP_WSC_PIN     12
#define UP_COUNTRY     13

#define LINKSYS		7
#define CISCO		90
#define	OTHER_OEM	99

#define ENGLISH 	1
#define JAPANESE	2
#define GERMAN		3
#define FRENCH		4
#define KOREAN		5

#define	USA		1
#define	JAPAN		2
#define	EUROPE		3
#define WW		4
#define GERMANY		5
#define	KOREA		6
#define	FRANCE		7

#define E300		1
#define E1550		2
#define E2500		3
#define E30X		4
#define E155X		5
#define E250X		6
#define E3200		7
#define E4200		8
#define E420X		9


//#define LINKSYS_MODEL E300 //E300
//#define LINKSYS_MODEL E1550 //E1550
//#define LINKSYS_MODEL E2500 //E2500
//#define LINKSYS_MODEL E30X //E30X
#define LINKSYS_MODEL E155X //E155X
//#define LINKSYS_MODEL E250X //E250X
//#define LINKSYS_MODEL E3200 //E3200
//#define LINKSYS_MODEL E4200 //E4200
//#define LINKSYS_MODEL E420X //E420X
/***************************************
 * define country                      *
 * LOCALE=COUNTRY =                    *
 ***************************************/
#define COUNTRY		LOCALE
#define LOCALE USA
//#define LOCALE JAPAN
//#define LOCALE EUROPE
//#define LOCALE WW
//#define LOCALE GERMANY	
//#define LOCALE FRANCE
//#define LOCALE KOREA
//#define LOCALE UK

/***************************************
 * define model name and code pattern  *
 * MODEL_NAME =                        *
 * CODE_PATTERN =                      *
 ***************************************/
#define OEM  LINKSYS

#if (OEM == LINKSYS)
	#define	CT_VENDOR		"LINKSYS"
	#define UI_STYLE		CISCO

	#if (LINKSYS_MODEL == E300)
		#define CODE_PATTERN   "61XN"
		#define MODEL_NUMBER	"E3000"	    //model number added by Jemmy 2009.11.17
		#define MODEL_NAME	"Linksys E3000"
		#define MODEL_VERSION	"V1"              //V1 or V2
		#define LINUX_VERSION	"2_4"             //2_4 or 2_6
	#elif (LINKSYS_MODEL == E1550)
		#define CODE_PATTERN   "1550"
		#define MODEL_NUMBER	"E1550"	    //model number
		#define MODEL_NAME	"Linksys E1550"
		#define MODEL_VERSION	"V1"              //V1 or V2
		#define LINUX_VERSION	"2_4"             //2_4 or 2_6
	#elif (LINKSYS_MODEL == E2500)
		#define CODE_PATTERN   "2500"
		#define MODEL_NUMBER	"E2500"	    //model number
		#define MODEL_NAME	"Linksys E2500"
		#define MODEL_VERSION	"V1"              //V1 or V2
		#define LINUX_VERSION	"2_4"             //2_4 or 2_6
	#elif (LINKSYS_MODEL == E30X)
		#define CODE_PATTERN   "61XN"
		#define MODEL_NUMBER	"E3000"	    //model number
		#define MODEL_NAME	"Linksys E3000"
		#define MODEL_VERSION	"V1"              //V1 or V2
		#define LINUX_VERSION	"2_6"             //2_4 or 2_6
	#elif (LINKSYS_MODEL == E155X)
		#define CODE_PATTERN   "1550"
		#define MODEL_NUMBER	"E1550"	    //model number
		#define MODEL_NAME	"Linksys E1550"
		#define MODEL_VERSION	"V1"              //V1 or V2
		#define LINUX_VERSION	"2_6"             //2_4 or 2_6
	#elif (LINKSYS_MODEL == E2500)
		#define CODE_PATTERN   "2500"
		#define MODEL_NUMBER	"E2500"	    //model number
		#define MODEL_NAME	"Linksys E2500"
		#define MODEL_VERSION	"V1"              //V1 or V2
		#define LINUX_VERSION	"2_6"             //2_4 or 2_6
	#elif (LINKSYS_MODEL == E3200)
		#define CODE_PATTERN   "3200"
		#define MODEL_NUMBER	"E3200"	    //model number
		#define MODEL_NAME	"Linksys E3200"
		#define MODEL_VERSION	"V1"              //V1 or V2
		#define LINUX_VERSION	"2_6"             //2_4 or 2_6
	#elif (LINKSYS_MODEL == E4200)
		#define CODE_PATTERN   "4200"
		#define MODEL_NUMBER	"E4200"	    //model number
		#define MODEL_NAME	"Linksys E4200"
		#define MODEL_VERSION	"V1"              //V1 or V2
		#define LINUX_VERSION	"2_4"             //2_4 or 2_6
	#elif (LINKSYS_MODEL == E420X)
		#define CODE_PATTERN   "4200"
		#define MODEL_NUMBER	"E4200"	    //model number
		#define MODEL_NAME	"Linksys E4200"
		#define MODEL_VERSION	"V1"              //V1 or V2
		#define LINUX_VERSION	"2_6"             //2_4 or 2_6
	#else
		#error "You must select a LINKSYS_MODEL!!"
	#endif

	#define INTEL_FLASH_SUPPORT_VERSION_FROM "v0.00.0"
	#define BCM4712_CHIP_SUPPORT_VERSION_FROM "v0.00.0"
	#define INTEL_FLASH_SUPPORT_BOOT_VERSION_FROM "v0.0"
	#define BCM4712_CHIP_SUPPORT_BOOT_VERSION_FROM "v0.0"

#else
	#error "Your must select a OEM name!!"
#endif

/***************************************
 * define language                     *
 * LANGUAGE =                          *
 * LANG_SEL=EN                         *
 * HTTP_CHARSET =		       *
 ***************************************/
#if (LOCALE == JAPAN)
	#define	LANGUAGE	JAPANESE
	#define	HTTP_CHARSET	"shift-jis"
#elif (LOCALE == GERMANY)
	#define LANGUAGE	GERMAN
	#define	HTTP_CHARSET	"iso-8859-1"
#elif (LOCALE == FRANCE)
	#define LANGUAGE	FRENCH
	#define	HTTP_CHARSET	"iso-8859-1"
#elif LOCALE == KOREA
	#define LANGUAGE 	KOREAN
	#define	HTTP_CHARSET	"euc-kr"
#else
	#define LANGUAGE 	ENGLISH
	#define	HTTP_CHARSET	"iso-8859-1"
#endif

/***************************************
 * define wireless max channel         *
 * WL_MAX_CHANNEL =                    *
 ***************************************/
#if ((LOCALE == JAPAN) || (LOCALE == EUROPE) || (LOCALE == GERMANY) || (LOCALE == FRANCE))
	#define	WL_MAX_CHANNEL	"13"
#else
	#define WL_MAX_CHANNEL	"11"
#endif

/***************************************
 * define web file path                *
 * WEB_PAGE =                          *
 ***************************************/
#if (OEM == LINKSYS)
 #if (UI_STYLE ==  CISCO)
	#if ((LINKSYS_MODEL == E300) || (LINKSYS_MODEL == E30X))
		#define WEB_PAGE        "cisco_wrt61xn_m"
	#elif ((LINKSYS_MODEL == E2500) || (LINKSYS_MODEL == E250X))
		#define WEB_PAGE        "cisco_e2500_m"
	#elif ((LINKSYS_MODEL == E1550) || (LINKSYS_MODEL == E155X))
		#define WEB_PAGE        "dvrf"
	#elif (LINKSYS_MODEL == E3200)
		#define WEB_PAGE        "dvrf"
	#elif ((LINKSYS_MODEL == E4200) || (LINKSYS_MODEL == E420X))
		#define WEB_PAGE        "cisco_ces_m"
	#else
		#error "unknown model for web page"
	#endif
 #else
	#error "unknown UI_STYLE"
 #endif
#elif (OEM == OTHER_OEM)
	#define WEB_PAGE	"nonbrand"
#else
	#error "unknown OEM customer"
#endif

/***************************************
 * check LOCALE
 ***************************************/
#if (OEM == LINKSYS)
 #if ((LOCALE != JAPAN) && (LOCALE != USA) && (LOCALE != EUROPE) && (LOCALE != GERMANY) && (LOCALE != FRANCE))
	#error	"The LOCALE for LINKSYS is error, must be USA, EUROPE, JAPAN, GERMANY or FRANCE"
 #endif
#elif (OEM == OTHER_OEM)
 #if ((LOCALE != USA) && (LOCALE != EUROPE))
	#error	"The LOCALE for NONBRAND is error, must be USA or EUROPE"
 #endif
#endif
