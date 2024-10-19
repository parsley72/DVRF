/*======================================================================
 *
 *          Copyright (C) 2010-2011 CyberTan Corporation
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *  Version: NA
 *
 * ----------------------------------------------------------------------------------
 *  File          :   generate_ula.c
 *
 *  Description   :   This is utility for generating ULA prefix.
 *
 *   It follows the RFC4193: Unique Local IPv6 Unicast Address,
 *   Section 3.2.2 Sample Code for Pseudo-Random Global ID Algorithm.
 *
 ======================================================================*/

#include <cy_conf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bcmnvram.h>
#include <error.h>
#ifdef POLARSSL_SUPPORT
#include <polarssl/sha1.h>
#else
#include <openssl/sha.h>
#endif

//#define	DBG(str, fmt...)	fprintf(stderr, str, fmt##)
#define	DBG(str, fmt...)

int main(int argc, char **argv)
{
	//fprintf(stderr, "cmdline=[%d,%s,%s,%s]\n", argc, argv[0], argv[1], argv[2]);
	unsigned char addrIPv6[16];
	unsigned char prefix = 0xFC;  //local IPv6 unicast address
	unsigned char L=1;  //the prefix is locally assigned
	unsigned char global_id[5];
	unsigned char subnet_id[2] = {0x0, 0x0};
	unsigned char interface_id[8];
	int bSave2Nvram = 0;

	// #generate_ula [ -nvram name ], it'll write ULA prefix to NVRAM instead of console.
	if (argc == 1) {
		bSave2Nvram=0;
	}
	else if ((argc == 3) && (strncmp(argv[1], "-nvram", 6) == 0)) {
		bSave2Nvram = 1;
	}
	else {
		fprintf(stdout, "Usage: generate_ula [ -nvram name ]\n");
		return (-1);
	}

	memset(addrIPv6, 0x0, sizeof(addrIPv6));

	addrIPv6[0] = (prefix | L);

	generate_global_id(global_id);
	memcpy(&addrIPv6[1], global_id, sizeof(global_id));

	memcpy(&addrIPv6[6], subnet_id, sizeof(subnet_id));

	generate_interface_id(interface_id);
	memcpy(&addrIPv6[8], interface_id, sizeof(interface_id));

	if (bSave2Nvram) {
		// 2011-07-27, add to resolve E4200 IR-B0017547
		unsigned char ula_prefix[40]={0};
		snprintf(ula_prefix, sizeof(ula_prefix),
			"%02X%02X:%02X%02X:%02X%02X:%02X%02X::",
			addrIPv6[0], addrIPv6[1], addrIPv6[2], addrIPv6[3],
			addrIPv6[4], addrIPv6[5], addrIPv6[6], addrIPv6[7]);
		nvram_set("ula_prefix", ula_prefix);

		unsigned char local_ula[40]={0};
		snprintf(local_ula, sizeof(local_ula),
			"%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
			addrIPv6[0], addrIPv6[1], addrIPv6[2], addrIPv6[3],
			addrIPv6[4], addrIPv6[5], addrIPv6[6], addrIPv6[7],
			addrIPv6[8], addrIPv6[9], addrIPv6[10], addrIPv6[11],
			addrIPv6[12], addrIPv6[13], addrIPv6[14], addrIPv6[15]);
		nvram_set(argv[2], local_ula);
		nvram_commit();
		//fprintf(stderr, "nvram_set=[%s,%s]\n", argv[2], prefix_ula);
	}
	else {
		fprintf(stdout, "(8 bits) Prefix+L:");
		fprintf(stdout, "%02X\n", addrIPv6[0]);

		fprintf(stdout, "(40 bits) Global ID:");
		fprintf(stdout, "%02X%02X%02X%02X%02X\n", 
			addrIPv6[1], addrIPv6[2], addrIPv6[3], addrIPv6[4], addrIPv6[5]);

		fprintf(stdout, "(16 bits) Subnet ID:");
		fprintf(stdout, "%02X%02X\n", addrIPv6[6], addrIPv6[7]);

		fprintf(stdout, "(64 bits) Interface ID:");
		fprintf(stdout, "%02X%02X%02X%02X%02X%02X%02X%02X\n", 
			addrIPv6[8], addrIPv6[9], addrIPv6[10], 
			addrIPv6[11], addrIPv6[12],
			addrIPv6[13], addrIPv6[14], addrIPv6[15]
		);
		fflush(stdout);
	}

	return 1;
}

//
// *OUTPUT global_id: 40-bit
//
int generate_global_id(unsigned char *global_id)
{
	unsigned char current_time_of_day[8];
	unsigned char eui64_identifier[8];

	unsigned char message[16];
	unsigned char message_digest[20]; //SHA_DIGEST_LENGTH

	//obtain the current time of day in 64-bit NTP format
	gettimeofday((struct timeval *) current_time_of_day, NULL);

	DBG("%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X\n", 
		current_time_of_day[0], current_time_of_day[1], 
		current_time_of_day[2], current_time_of_day[3], 
		current_time_of_day[4], current_time_of_day[5], 
		current_time_of_day[6], current_time_of_day[7]
	);

	//obtain an EUI-64 identifier from a 48-bit MAC address
	memset(eui64_identifier, 0x0, sizeof(eui64_identifier));
	generate_interface_id(eui64_identifier);

	DBG("%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X\n", 
		eui64_identifier[0], eui64_identifier[1], eui64_identifier[2], 
		eui64_identifier[3], eui64_identifier[4], 
		eui64_identifier[5], eui64_identifier[6], eui64_identifier[7]
	);

	//concatenate the time of day with EUI-64 identifier to create a key
	memset(message, 0x0, sizeof(message));
	memcpy(&message[0], current_time_of_day, 8 /*bytes*/);
	memcpy(&message[8], eui64_identifier, 8 /*bytes*/);

	//compute an SHA-1 digest on the key
	#ifdef POLARSSL_SUPPORT
	sha1(message, 8+8, message_digest);
	#else
	SHA1(message, 8+8, message_digest);
	#endif

	//retrieve the least significant 40 bits as the Global ID
	memcpy(global_id, &message_digest[0], 5 /*bytes*/);

	return 1;
}

//
// *OUTPUT eui64_identifier: 64-bit
//
int generate_interface_id(unsigned char *eui64_identifier)
{
	unsigned char *str_mac = nvram_safe_get("lan_hwaddr");

	//obtain an EUI-64 identifier from a 48-bit MAC address
	sscanf(str_mac, "%x:%x:%x:%x:%x:%x", 
		&eui64_identifier[0], &eui64_identifier[1], &eui64_identifier[2], 
		&eui64_identifier[5], &eui64_identifier[6], &eui64_identifier[7]
	);
	eui64_identifier[0] ^= 2;
	eui64_identifier[3] = 0xFF;
	eui64_identifier[4] = 0xFE;

	return 1;
}

