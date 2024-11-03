/* Shared library add-on to iptables to add string matching support. 
 * 
 * Copyright (C) 2000 Emmanuel Roger  <winfield@freegates.be>
 *
 * ChangeLog
 *     27.01.2001: Gianni Tedesco <gianni@ecsc.co.uk>
 *             Changed --tos to --string in save(). Also
 *             updated to work with slightly modified
 *             ip6t_string_info.
 */

/* Shared library add-on to iptables to add webstr matching support. 
 *
 * Copyright (C) 2003, CyberTAN Corporation
 * All Rights Reserved.
 *
 * Description:
 *   This is shared library, added to iptables, for web content inspection. 
 *   It was derived from 'string' matching support, declared as above.
 *
 */

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <ip6tables.h>
#include <linux/netfilter_ipv6/ip6t_webstr.h>

//#define exit_error iptables_exit_error
//#define check_inverse xtables_check_inverse

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"WEBSTR match options:\n"
"--webstr [!] host            Match a http string in a packet\n"
"--webstr [!] url             Match a http string in a packet\n"
"--webstr [!] content         Match a http string in a packet\n"
"--http_init [!] wlist        Match a http three-way handshake packet\n"
"--http [!] wlist             Match a http string in a packet\n"
"--https [!] wlist            Match a https string in a packet\n"
XTABLES_VERSION );
	fputc('\n', stdout);
}

static const struct option opts[] = {
	{ "host", 	1, NULL, '1' },
	{ "url", 	1, NULL, '2' },
	{ "content", 	1, NULL, '3' },
	{ "http_init",  1, NULL, '4' },
	{ "http",       1, NULL, '5' },
	{ "https",      1, NULL, '6' },
	{ .name = NULL }
};

#if 0 
/* Initialize the match. */
static void
init(struct xt_entry_match *m, unsigned int *nfcache)
{
	*nfcache |= NFC_UNKNOWN;
}
#endif

static void
parse_string(const unsigned char *s, struct ip6t_webstr_info *info)
{	
        if (strlen(s) <= BM_MAX_NLEN) strcpy(info->string, s);
	else exit_error(PARAMETER_PROBLEM, "WEBSTR too long `%s'", s);
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const void *entry, struct xt_entry_match **match)
{
	struct ip6t_webstr_info *stringinfo = (struct ip6t_webstr_info *)(*match)->data;

	switch (c) {
	case '1':
		check_inverse(optarg, &invert, &optind, 0);
		parse_string(argv[optind-1], stringinfo);
		if (invert)
			stringinfo->invert = 1;
                stringinfo->len=strlen((char *)&stringinfo->string);
                stringinfo->type = IP6T_WEBSTR_HOST;
		break;

	case '2':
		check_inverse(optarg, &invert, &optind, 0);
		parse_string(argv[optind-1], stringinfo);
		if (invert)
			stringinfo->invert = 1;
                stringinfo->len=strlen((char *)&stringinfo->string);
                stringinfo->type = IP6T_WEBSTR_URL;
		break;

	case '3':
		check_inverse(optarg, &invert, &optind, 0);
		parse_string(argv[optind-1], stringinfo);
		if (invert)
			stringinfo->invert = 1;
                stringinfo->len=strlen((char *)&stringinfo->string);
                stringinfo->type = IP6T_WEBSTR_CONTENT;
		break;

	case '4':
		check_inverse(optarg, &invert, &optind, 0);
		parse_string(argv[optind-1], stringinfo);
		if (invert)
			stringinfo->invert = 1;
		stringinfo->len=strlen((char *)&stringinfo->string);
		stringinfo->type = IP6T_WEBSTR_HTTP_INIT;
		break;

	case '5':
		check_inverse(optarg, &invert, &optind, 0);
		parse_string(argv[optind-1], stringinfo);
		if (invert)
			stringinfo->invert = 1;
		stringinfo->len=strlen((char *)&stringinfo->string);
		stringinfo->type = IP6T_WEBSTR_HTTP_WLIST;
		break;

	case '6':
		check_inverse(optarg, &invert, &optind, 0);
		parse_string(argv[optind-1], stringinfo);
		if (invert)
			stringinfo->invert = 1;
		stringinfo->len=strlen((char *)&stringinfo->string);
		stringinfo->type = IP6T_WEBSTR_HTTPS_WLIST;
		break;

	default:
		return 0;
	}

	*flags = 1;
	return 1;
}

static void
print_string(char string[], int invert, int numeric)
{

	if (invert)
		fputc('!', stdout);
	printf("%s ",string);
}

/* Final check; must have specified --string. */
static void
final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
			   "WEBSTR match: You must specify `--webstr'");
}

/* Prints out the matchinfo. */
static void
print(const void *ip,
      const struct xt_entry_match *match,
      int numeric)
{
	struct ip6t_webstr_info *stringinfo = (struct ip6t_webstr_info *)match->data;

	printf("WEBSTR match ");

	
	switch (stringinfo->type) {
	case IP6T_WEBSTR_HOST:
		printf("host ");
		break;

	case IP6T_WEBSTR_URL:
		printf("url ");
		break;

	case IP6T_WEBSTR_CONTENT:
		printf("content ");
		break;

	case IP6T_WEBSTR_HTTP_INIT:
		printf("http_init ");
		break;

	case IP6T_WEBSTR_HTTP_WLIST:
		printf("http ");
		break;

	case IP6T_WEBSTR_HTTPS_WLIST:
		printf("https ");
		break;

	default:
		printf("ERROR ");
		break;
	}

	print_string(((struct ip6t_webstr_info *)match->data)->string,
		  ((struct ip6t_webstr_info *)match->data)->invert, numeric);
}

/* Saves the union ip6t_matchinfo in parsable form to stdout. */
static void save(const void *ip, const struct xt_entry_match *match)
{
	printf("--webstr ");
	print_string(((struct ip6t_webstr_info *)match->data)->string,
		  ((struct ip6t_webstr_info *)match->data)->invert, 0);
}

static struct xtables_match webstr = { 
	.name		= "webstr",
	.version	= XTABLES_VERSION,
	.family		= PF_INET6,
	.size		= XT_ALIGN(sizeof(struct ip6t_webstr_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ip6t_webstr_info)),
	.help		= help,
	//.init		= init,
	.parse		= parse,
	.final_check	= final_check,
	.print		= print,
	.save		= save,
	.extra_opts	= opts
};

void _init(void)
{
	xtables_register_match(&webstr);
}

