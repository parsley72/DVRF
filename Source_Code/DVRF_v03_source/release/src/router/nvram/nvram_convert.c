/*
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
 * $Id: nvram_convert.c,v 1.1.1.9 2007/05/31 08:00:31 michael Exp $
 */

#include "nvram_convert.h"
#include <code_pattern.h>

#ifdef LINUX26
/* Lai 2010.04.20 add to support Simultaneous/Selective dual band wireless. */
#define WL24(a)		a"_24g"
#define WL5g(a)		a"_5g"
#define CAP(a)		a"_cap"
#endif

#define WL(a)	"wl_"a	
#define WL0(a)	"wl0_"a	
#define WL1(a)	"wl1_"a		//Jemmy add for dual band wireless 2008.3.1
#define D11G(a)	"d11g_"a
//Jemmy add for enable guest network mac filter  2009.10.8
#define WL01(a) "wl0.1_"a

#define PPP(a)		"ppp_"a
#define PPPOE(a)	"pppoe_"a


struct nvram_convert nvram_converts[] = {
#ifdef LINUX26
#if ( (LINKSYS_MODEL == E155X) || \
      (LINKSYS_MODEL == E250X) || \
      (LINKSYS_MODEL == E3200) || \
      (LINKSYS_MODEL == E420X) )
	/*
	 * xxx_24g	-->	wl0_xxx
	 * xxx_5g	-->	wl1_xxx
	 */
	{ WL24("ssid"), 	WL0("ssid"), 		"",		""},
	{ WL5g("ssid"), 	"", 			WL1("ssid"),	""},
	{ WL24("net_mode"),	WL0("net_mode"),	"",		""},
	{ WL5g("net_mode"),	"", 			WL1("net_mode"),""},
	{ WL24("nbw"),		WL0("nbw"),		"",		""},
	{ WL24("nbw_cap"),	WL0("nbw_cap"),		"",		""},
	{ WL5g("nbw"),		"", 			WL1("nbw"),	""},
	{ WL5g("nbw_cap"),	"", 			WL1("nbw_cap"),	""},
	{ WL24("channel"),	WL0("channel"),		"",		""},
	{ WL5g("channel"),	"", 			WL1("channel"),	""},
	{ WL24("closed"),	WL0("closed"),		"",		""},
	{ WL5g("closed"),	"", 			WL1("closed"),	""},

	/* below list just for HNAP. */
	{ WL24("akm"), 		WL0("akm"), 		"",		""},
	{ WL5g("akm"), 		"", 			WL1("akm"),	""},
	{ WL24("auth"), 	WL0("auth"), 		"",		""},
	{ WL5g("auth"), 	"", 			WL1("auth"),	""},
	{ WL24("auth_mode"),	WL0("auth_mode"), 	"",		""},
	{ WL5g("auth_mode"),	"", 		WL1("auth_mode"),	""},
	{ WL24("auth_type"), 	WL0("auth_type"), 	"",		""},
	{ WL5g("auth_type"), 	"", 		WL1("auth_type"),	""},
	{ WL24("crypto"), 	WL0("crypto"), 		"",		""},
	{ WL5g("crypto"), 	"", 		WL1("crypto"),		""},
	{ WL24("wep"),		WL0("wep"), 		"",		""},
	{ WL5g("wep"),		"", 		WL1("wep"),		""},
	{ WL24("wep_buf"),		WL0("wep_buf"), 		"",		""},
	{ WL5g("wep_buf"),		"", 		WL1("wep_buf"),		""},
	{ WL24("wep_gen"),		WL0("wep_gen"), 		"",		""},
	{ WL5g("wep_gen"),		"", 		WL1("wep_gen"),		""},
	{ WL24("key"),		WL0("key"), 		"",		""},
	{ WL5g("key"),		"", 		WL1("key"),		""},
	{ WL24("key1"), 	WL0("key1"), 		"",		""},
	{ WL5g("key1"), 	"", 			WL1("key1"),	""},
	{ WL24("nctrlsb"), 	WL0("nctrlsb"), 	"",		""},
	{ WL5g("nctrlsb"), 	"", 			WL1("nctrlsb"),	""},
	{ WL24("passphrase"), 	WL0("passphrase"), 	"",		""},
	{ WL5g("passphrase"), 	"", 		WL1("passphrase"),	""},
	{ WL24("radius_ipaddr"),WL0("radius_ipaddr"), 	"",		""},
	{ WL5g("radius_ipaddr"),"",		WL1("radius_ipaddr"),	""},
	{ WL24("radius_key"), 	WL0("radius_key"), 	"",		""},
	{ WL5g("radius_key"), 	"", 		WL1("radius_key"),	""},
	{ WL24("radius_port"), 	WL0("radius_port"), 	"",		""},
	{ WL5g("radius_port"), 	"", 		WL1("radius_port"),	""},
	{ WL24("security_mode"),WL0("security_mode"), 	"",		""},
	{ WL5g("security_mode"),"", 		WL1("security_mode"),	""},
	{ WL24("wep_bit"), 	WL0("wep_bit"), 	"",		""},
	{ WL5g("wep_bit"), 	"", 			WL1("wep_bit"),	""},
	{ WL24("wme"),		WL0("wme"), 		WL1("wme"),		""},
	{ WL5g("wme"),		WL0("wme"), 		WL1("wme"),		""},
	{ WL24("wpa_gtk_rekey"),WL0("wpa_gtk_rekey"),	"",		""},
	{ WL5g("wpa_gtk_rekey"),"", 		WL1("wpa_gtk_rekey"),	""},
	{ WL24("wpa_psk"), 	WL0("wpa_psk"), 	"",		""},
	{ WL5g("wpa_psk"), 	"", 			WL1("wpa_psk"),	""},
	{ WL24("wps_config_state"), WL0("wps_config_state"), 	"",	""},
	{ WL5g("wps_config_state"), "",	WL1("wps_config_state"),	""},
	{ "wl0_hwaddr", 	"hwaddr_24g", 		"",		""},
	{ "wl1_hwaddr", 	"", 			"hwaddr_5g",	""},
#elif ( LINKSYS_MODEL == E200 )
	/*
	 * xxx_24g	-->	wl0_xxx
	 * xxx_5g	-->	wl0_xxx
	 */
	{ WL24("ssid"), 	WL0("ssid"), 		"",		""},
	{ WL5g("ssid"), 	WL0("ssid"), 		"",		""},
	{ WL24("net_mode"),	WL0("net_mode"), 	"",		""},
	{ WL5g("net_mode"),	WL0("net_mode"), 	"",		""},
	{ WL24("nbw"),		WL0("nbw"), 		"",		""},
	{ CAP("nbw_24g"),	WL0("nbw_cap"), 	"",		""},
	{ WL5g("nbw"), 		WL0("nbw"), 		"",		""},
	{ CAP("nbw_5g"),	WL0("nbw_cap"), 	"",		""},
	{ WL24("channel"),	WL0("channel"), 	"",		""},
	{ WL5g("channel"), 	WL0("channel"), 	"",		""},
	{ WL24("closed"),	WL0("closed"), 		"",		""},
	{ WL5g("closed"), 	WL0("closed"), 		"",		""},
	{ WL24("rate"),		WL0("rate"), 		"",		""},
	{ WL5g("rate"),		WL0("rate"), 		"",		""},

	/* below list just for HNAP. */
	{ WL24("akm"), 		WL0("akm"), 		"",		""},
	{ WL5g("akm"), 		WL0("akm"),		"",		""},
	{ WL24("auth"), 	WL0("auth"), 		"",		""},
	{ WL5g("auth"), 	WL0("auth"), 		"",		""},
	{ WL24("auth_mode"),	WL0("auth_mode"), 	"",		""},
	{ WL5g("auth_mode"),	WL0("auth_mode"), 	"",		""},
	{ WL24("auth_type"),	WL0("auth_type"), 	"",		""},
	{ WL5g("auth_type"),	WL0("auth_type"), 	"",		""},
	{ WL24("crypto"), 	WL0("crypto"), 		"",		""},
	{ WL5g("crypto"), 	WL0("crypto"), 		"",		""},
	{ WL24("wep"),		WL0("wep"), 		"",		""},
	{ WL5g("wep"),		WL0("wep"),, 		"",		""},
	{ WL24("wep_buf"),		WL0("wep_buf"), 		"",		""},
	{ WL5g("wep_buf"),		WL0("wep_buf"), 		"",		""},
	{ WL24("wep_gen"),		WL0("wep_gen"), 		"",		""},
	{ WL5g("wep_gen"),		WL0("wep_gen"), 		"",		""},
	{ WL24("key"),		WL0("key"), 		"",		""},
	{ WL5g("key"),		WL0("key"), 		"",		""},
	{ WL24("key1"),		WL0("key1"), 		"",		""},
	{ WL5g("key1"),		WL0("key1"), 		"",		""},
	{ WL24("nctrlsb"), 	WL0("nctrlsb"), 	"",		""},
	{ WL5g("nctrlsb"), 	WL0("nctrlsb"), 	"",		""},
	{ WL24("passphrase"),	WL0("passphrase"), 	"",		""},
	{ WL5g("passphrase"),	WL0("passphrase"), 	"",		""},
	{ WL24("radius_ipaddr"),WL0("radius_ipaddr"), 	"",		""},
	{ WL5g("radius_ipaddr"),WL0("radius_ipaddr"), 	"",		""},
	{ WL24("radius_key"), 	WL0("radius_key"), 	"",		""},
	{ WL5g("radius_key"), 	WL0("radius_key"), 	"",		""},
	{ WL24("radius_port"), 	WL0("radius_port"), 	"",		""},
	{ WL5g("radius_port"), 	WL0("radius_port"), 	"",		""},
	{ "security_mode_0", 	"security_mode", 	"",		""},
	{ "security_mode_1", 	"security_mode", 	"",		""},
	{ WL24("security_mode"), WL0("security_mode"), 	"",		""},
	{ WL5g("security_mode"), WL0("security_mode"), 	"",		""},
	{ WL24("wep_bit"), 	WL0("wep_bit"), 	"",		""},
	{ WL5g("wep_bit"), 	WL0("wep_bit"), 	"",		""},
	{ WL24("wme"),		WL0("wme"), 		"",		""},
	{ WL5g("wme"),		WL0("wme"), 		"",		""},
	{ WL24("wpa_gtk_rekey"),WL0("wpa_gtk_rekey"), 	"",		""},
	{ WL5g("wpa_gtk_rekey"),WL0("wpa_gtk_rekey"), 	"",		""},
	{ WL24("wpa_psk"), 	WL0("wpa_psk"), 	"",		""},
	{ WL5g("wpa_psk"), 	WL0("wpa_psk"), 	"",		""},
	{ WL24("wps_config_state"), WL0("wps_config_state"), 	"",	""},
	{ WL5g("wps_config_state"), WL0("wps_config_state"), 	"",	""},
	{ "wl0_hwaddr", 	"hwaddr_24g", 		"hwaddr_5g",	""},
#else
	/*
	 * xxx_24g	-->	wl0_xxx
	 */
	{ WL24("ssid"), 	WL0("ssid"), 		"",		""},
	{ WL24("net_mode"),	WL0("net_mode"), 	"",		""},
	{ WL24("nbw"),		WL0("nbw"), 		"",		""},
	{ CAP("nbw_24g"),	WL0("nbw_cap"), 	"",		""},
	{ WL24("channel"),	WL0("channel"), 	"",		""},
	{ WL24("closed"),	WL0("closed"), 		"",		""},
#endif
#endif //LINUX26

	//Jemmy remove these wireless setting except macfilter 2008.5.15
#if 0
	// Bellow change from 3.11.48.7
	//{ WL("ssid"),	 	WL0("ssid"),	 	WL1("ssid"),	""},
	{ WL("mode"), 		WL0("mode"),	 	WL1("mode"),	""},
	{ WL("wds"), 		WL0("wds"),	 	WL1("wds"),	""},
	{ WL("auth"), 		WL0("auth"),	 	WL1("auth"),	""},
	{ WL("key"), 		WL0("key"), 	 	WL1("key"),	""},
	{ WL("key1"), 		WL0("key1"), 	 	WL1("key1"),	""},
	{ WL("key2"), 		WL0("key2"),	 	WL1("key2"),	""},
	{ WL("key3"), 		WL0("key3"),	 	WL1("key3"),	""},
	{ WL("key4"), 		WL0("key4"),	 	WL1("key4"),	""},
	{ WL("channel"), 	WL0("channel"), 	WL1("channel"), 	D11G("channel")},
	{ WL("rateset"), 	WL0("rateset"), 	WL1("rateset"),		D11G("rateset")},
	{ WL("rts"), 		WL0("rts"), 		WL1("rts"),		D11G("rts")},
	{ WL("bcn"), 		WL0("bcn"),		WL1("bcn"),		D11G("bcn")},
	{ WL("gmode"), 		WL0("gmode"),		WL1("gmode"), 		"d11g_mode"},
	{ WL("unit"), 		WL0("unit"),		WL1("unit"), 	""},
	{ WL("ifname"), 	WL0("ifname"),		WL1("ifname"),	""},
	{ WL("phytype"), 	WL0("phytype"),		WL1("phytype"),	""},
	{ WL("country"), 	WL0("country"),		WL1("country"),	""},
	{ WL("country_code"), 	WL0("country_code"),	WL1("country_code"),	""},
	{ WL("closed"), 	WL0("closed"),		WL1("closed"),	""},
	{ WL("lazywds"), 	WL0("lazywds"),		WL1("lazywds"),	""},
	{ WL("wep"), 		WL0("wep"),		WL1("wep"),	""},
	{ WL("rate"), 		WL0("rate"),		WL1("rate"), 	D11G("rate")},
	{ WL("frag"), 		WL0("frag"),		WL1("frag"),	D11G("frag")},
	{ WL("dtim"), 		WL0("dtim"),		WL1("dtim"), 	D11G("dtim")},
	{ WL("plcphdr"), 	WL0("plcphdr"),		WL1("plcphdr"),	""},
	{ WL("gmode_protection"), 	WL0("gmode_protection"),		WL1("gmode_protection"),	""},
	{ WL("radio"), 		WL0("radio"),		WL1("radio"),	""},
	// Below change from 3.21.9.0
	{ WL("auth_mode"), 	WL0("auth_mode"),	WL1("auth_mode"),	""},
	{ WL("radius_ipaddr"), 	WL0("radius_ipaddr"),	WL1("radius_ipaddr"),	""},
	{ WL("radius_port"), 	WL0("radius_port"),	WL1("radius_port"),	""},
	{ WL("radius_key"), 	WL0("radius_key"),	WL1("radius_key"),	""},
	{ WL("wpa_psk"), 	WL0("wpa_psk"),		WL1("wpa_psk"),		""},
	{ WL("wpa_gtk_rekey"), 	WL0("wpa_gtk_rekey"),	WL1("wpa_gtk_rekey"),	""},
	{ WL("frameburst"), 	WL0("frameburst"),	WL1("frameburst"),	""},
	{ WL("crypto"), 	WL0("crypto"),		WL1("crypto"),		""},
	{ WL("ap_isolate"), 	WL0("ap_isolate"),	WL1("ap_isolate"),	""},
	{ WL("afterburner"), 	WL0("afterburner"),	WL1("afterburner"),	""},
	// Below change from 3.63.13.1
	{ WL("akm"),            WL0("akm"),		WL1("akm"),  		""},
	{ WL("preauth"),        WL0("preauth"),		WL1("preauth"), 	""},
	{ WL("wme"),  	        WL0("wme"),		WL1("wme"), 		""},
	{ WL("wme_sta_bk"),     WL0("wme_sta_bk"),	WL1("wme_sta_bk"), 	""},
	{ WL("wme_sta_be"),     WL0("wme_sta_be"),	WL1("wme_sta_be"), 	""},
	{ WL("wme_sta_vi"),     WL0("wme_sta_vi"),	WL1("wme_sta_vi"), 	""},
	{ WL("wme_sta_vo"),     WL0("wme_sta_vo"),	WL1("wme_sta_vo"), 	""},
	{ WL("wme_ap_bk"),      WL0("wme_ap_bk"),	WL1("wme_ap_bk"), 	""},
	{ WL("wme_ap_be"),      WL0("wme_ap_be"),	WL1("wme_ap_be"), 	""},
	{ WL("wme_ap_vi"),      WL0("wme_ap_vi"),	WL1("wme_ap_vi"), 	""},
	{ WL("wme_ap_vo"),      WL0("wme_ap_vo"),	WL1("wme_ap_vo"), 	""},
	{ WL("wme_no_ack"),     WL0("wme_no_ack"),	WL1("wme_no_ack"), 	""},
	{ WL("wme_apsd"),       WL0("wme_apsd"),	WL1("wme_apsd"), 	""},
	{ WL("mrate"), 		WL0("mrate"),		WL1("mrate"), 		""},
	{ WL("maxassoc"), 	WL0("maxassoc"),	WL1("maxassoc"), 	""},
	{ WL("ure"), 		WL0("ure"),		WL1("ure"), 		""},
	{ WL("wds_timeout"),	WL0("wds_timeout"),	WL1("wds_timeout"),	""},
	//{ WL("nbw"),		WL0("nbw"),		WL1("nbw"),		""},
	//{ WL("nbw_cap"),	WL0("nbw_cap"),		WL1("nbw_cap"),		""},
	{ WL("nctrlsb"),	WL0("nctrlsb"),		WL1("nctrlsb"),		""},
	//{ WL("nband"),		WL0("nband"),		WL1("nband"),		""}, Jemmy remove this 2008.3.31
	{ WL("nmcsidx"),	WL0("nmcsidx"),		WL1("nmcsidx"),		""},
	{ WL("nstf"),		WL0("nstf"),		WL1("nstf"),		""},
	{ WL("nmode_protection"), 	WL0("nmode_protection"),		WL1("nmode_protection"),	""},
	{ WL("amsdu"), 		WL0("amsdu"),		WL1("amsdu"),		""},
	{ WL("ampdu"), 		WL0("ampdu"),		WL1("ampdu"),		""},
	{ WL("nmode"), 		WL0("nmode"),		WL1("nmode"),		""},
	{ WL("nreqd"), 		WL0("nreqd"),		WL1("nreqd"),		""},
	{ WL("vlan_prio_mode"),	WL0("vlan_prio_mode"),	WL1("vlan_prio_mode"),	""},
	{ WL("leddc"),		WL0("leddc"),		WL1("leddc"),		""},
	{ WL("wsc_mode"),	WL0("wsc_mode"),	WL1("wsc_mode"),	""},

	// for dual band wireless 2008.2.29	
	{ WL("net_mode"),	WL0("net_mode"),	WL1("net_mode"),	""},
	{ WL("widechannel"),	WL0("widechannel"),	WL1("widechannel"),	""},
	{ WL("security_mode"),	WL0("security_mode"),	WL1("security_mode"),	""},
	{ WL("txpwr"),		WL0("txpwr"),		WL1("txpwr"),		""},
#endif
	//Jemmy add for enable guest network mac filter  2009.10.8
	{ WL("macmode"), 	WL0("macmode"),		WL1("macmode"),	WL01("macmode")},
	{ WL("maclist"), 	WL0("maclist"),		WL1("maclist"),	WL01("maclist")},

	// for PPPoE
	{ PPP("username"), 	PPPOE("username"),	"",	""},
	{ PPP("passwd"), 	PPPOE("passwd"),	"",	""},
	{ PPP("idletime"), 	PPPOE("idletime"),	"",	""},
	{ PPP("keepalive"), 	PPPOE("keepalive"),	"",	""},
	{ PPP("demand"), 	PPPOE("demand"),	"",	""},
	{ PPP("service"), 	PPPOE("service"),	"",	""},
	{ PPP("ac"), 		PPPOE("ac"),		"",	""},
	{ PPP("static"),	PPPOE("static"),	"",	""},
	{ PPP("static_ip"), 	PPPOE("static_ip"),	"",	""},
	{ PPP("username_1"), 	PPPOE("username_1"),	"",	""},
	{ PPP("passwd_1"), 	PPPOE("passwd_1"),	"",	""},
	{ PPP("idletime_1"), 	PPPOE("idletime_1"),	"",	""},
	{ PPP("keepalive_1"), 	PPPOE("keepalive_1"),	"",	""},
	{ PPP("demand_1"), 	PPPOE("demand_1"),	"",	""},
	{ PPP("service_1"), 	PPPOE("service_1"),	"",	""},
	{ PPP("ac_1"), 		PPPOE("ac_1"),		"",	""},
	{ 0, 0, 0, 0},
};
