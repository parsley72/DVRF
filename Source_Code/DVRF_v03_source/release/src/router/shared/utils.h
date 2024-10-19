#include "../../cy_conf.h"
#include <code_pattern.h>

extern time_t time_wrap(time_t *tm);
//add by michael to fix SQA 18798 at 20090603
extern time_t time_wrap_new(time_t *tm);
//add by michael for check process alive at 20110316
extern int is_process_alive(char *ppid, char *pidname);
extern unsigned long random_num(void);
extern int diag_led(int type, int act);
extern int C_led(int i);
extern int get_single_ip(char *ipaddr, int which);
extern char *get_mac_from_ip(char *ip);
extern char *get_ip_from_mac(char *mac);
//add by michael to add dhcp-pptp function at 20080331
#ifdef PPTP_DHCPC_SUPPORT
extern struct dns_lists *pptp_get_dns_list(int no);
#endif
//end by michael 
extern struct dns_lists *get_dns_list(int no);
extern int dns_to_resolv(void);
extern char *get_wan_face(void);
extern int check_wan_link(int num);
//Jemmy add 2009.9.21
extern int check_port_cable(int port_num);

extern char *get_complete_lan_ip(char *ip);
extern char *get_complete_ip(char *from, char *to);
extern int get_int_len(int num);
extern int file_to_buf(char *path, char *buf, int len);
extern int buf_to_file(char *path, char *buf);
#ifdef HSIAB_SUPPORT
extern char *send_command(char *send_value, char *get_value);
extern struct database * open_DB1(int *c);
extern int init_hsiabd(void);
#endif
extern pid_t* find_pid_by_name( char* pidName);
extern int find_pid_by_ps(char* pidName);
extern int *find_all_pid_by_ps(char* pidName);
extern char *find_name_by_proc(int pid);
extern int get_ppp_pid(char *file);
#ifdef MPPPOE_SUPPORT
extern int get_pppoe_num(char *filename);  //by tallest
extern void wait_pppoe(int times);	// by tallest
extern char pppoe_in_use;  //tallest 1216
#endif
extern long convert_ver(char *ver);
extern int check_flash(void);
extern int check_action(void);
extern int check_now_boot(void);
extern int check_hw_type(void);
extern void show_hw_type(int type);
extern int is_exist(char *filename);
extern void set_ip_forward(char c);
#define MAX_GRP                20
#define NR_RULES               10
#define CTF_SUPPORT
#ifdef CTF_SUPPORT
void ctf_set_wanip(void);
void clear_ctf_entries(void);
void ctf_ipc_del_by_ip_range(unsigned int begin, unsigned int end);
void ctf_ipc_del_by_port_range(unsigned int begin, unsigned int end);
void ctf_ipc_del_by_mac(const char * mac);
void ctf_add_filter(void);
#endif
struct mtu_lists *get_mtu(char *proto);
extern void set_host_domain_name(void);
extern int is_wireless_mac(char *mac);
//add by michael to fix the wl interface will change to LAN when the wl client goto sleep at 20110504
extern int check_is_wireless_mac(char *mac);
extern int check_wl_type(char *mac);

#ifdef GUEST_NETWORK_SUPPORT
extern int check_wl_type_all(char *mac);
extern int detect_wan_cable_plug(void);
#endif

//add by michael to fix the l2tp can't ping l2tp server at 20090521
extern int is_same_subnet(char *sip, char *mask, char *dip);

extern void encode(char *buf, int len);
extern void decode(char *buf, int len);
extern struct code_header *init_code_header(int flag);
extern int generate_md5sum_main(void);

extern int first_time(void);

#ifdef WSC_SUPPORT
#define PIN_CODE_LEN 9 
extern void wsc_generate_pin(char *wsc_pin);
#if ( (LINKSYS_MODEL == E1550) || (LINKSYS_MODEL == E155X) || \
      (LINKSYS_MODEL == E2500) || (LINKSYS_MODEL == E250X) || \
      (LINKSYS_MODEL == E3200) || \
      (LINKSYS_MODEL == E4200) || (LINKSYS_MODEL == E420X) )
extern int wps_gui_set(char *type);
extern int set_wps_env(char *uibuf);
#else
#error "Unkown model, not setting GPIO enum"
#endif
#endif

#if defined(HW_QOS_SUPPORT) || defined(PERFORMANCE_SUPPORT)
extern int set_register_value(unsigned short port_addr, unsigned short option_content);
extern unsigned long get_register_value(unsigned short id, unsigned short num);
extern int get_register(unsigned short page_num, unsigned short addr_num,int byte_len);
extern int set_register(unsigned short page_num, unsigned short addr_num, void *data,int byte_len);
//extern int sys_netdev_ioctl(int family, int socket, char *if_name, int cmd, struct ifreq *ifr);

enum
{   
    QOS_BOTH = 0,
    QOS_TCP,
    QOS_UDP
};

enum
{   
    QOS_LOW = 0,
    QOS_NORMAL = 1,
    QOS_MEDIUM = 2,
    QOS_HIGH = 3
};

enum
{   
    QOS_APPL = 1,
    QOS_ONLINE_GAME,
    QOS_MAC_ADDR,
    QOS_ETHER_PORT,
    QOS_VOICE_DEV
};
/*
  here is for QoS & Firewall parse NVRAM Rule
  Nv_Ram RuleName is "QoS_Rule_x" here 'x' is QoS_cnt
*/
struct QoS_Rule_t
{
        unsigned short Category;
        unsigned short sub_num;
        char sub_name[33];
        unsigned short priority;
        
        union
        {
             struct 
             {
                    unsigned short sport[3];
                    unsigned short eport[3];
                    unsigned short proto[3];
             }port_opt;
             struct 
             {
                    char mac[18];
             }mac_addr;
             struct 
             {
                    unsigned short flow_control;
                    unsigned short port_rate_limit;
             }eth_port;
        }detail;
};

extern int parse_qos_rule(char *str_rule, struct QoS_Rule_t *QoS_Rule); /*2006/03/15 Jack add*/

/* for QoS */
#define QOS_MAX_WAN_SPEED				(95 * 1024) // 97280 kbps
#define QOS_MAX_LAN_SPEED				QOS_MAX_WAN_SPEED
#define CTF_QOS_MAX_WAN_SPEED			(440 * 1024) // 450560 kbps
#define CTF_QOS_MAX_LAN_SPEED			CTF_QOS_MAX_WAN_SPEED
#define QOS_MIN_WAN_SPEED				128
#define QOS_MIN_LAN_SPEED				QOS_MIN_WAN_SPEED

#define STR_QOS_MAX_WAN_SPEED			"97280"
#define STR_QOS_MAX_LAN_SPEED			STR_QOS_MAX_WAN_SPEED
#define STR_CTF_QOS_MAX_WAN_SPEED		"450560"
#define STR_CTF_QOS_MAX_LAN_SPEED		STR_CTF_QOS_MAX_WAN_SPEED
#define STR_QOS_MIN_WAN_SPEED			"128"
#define STR_QOS_MIN_LAN_SPEED			STR_QOS_MIN_WAN_SPEED

#endif

int ct_openlog(const char *ident, int option, int facility, char *log_name);
void ct_syslog(int level, int enable, const char *fmt,...);
void ct_logger(int level, const char *fmt,...);
struct wl_assoc_mac * get_wl_assoc_mac(int *c);
//add by michael to change the apply action of set macfilter at 20080804
struct wl_assoc_mac * get_wl_band_assoc_mac(int *c,char *band);
//end by michael
struct arp_table * get_arp_table(int *c);
struct host_table * combine_wl_arp_dhcp(int *c);

struct arp_table * get_arp_table_role(int *c,int role);
struct dhcp_table * get_dhcp_table_role(int *c, int role);
struct wl_assoc_mac * get_wl_assoc_mac_role(int *c,int role);

#ifdef CES_MDNS_SUPPORT
struct cesmdns_host_table * get_cesmdns_table(int *c);
#endif

#ifdef NMBD_NAME_REGISTER_SUPPORT
struct netbios_host_table * get_netbios_table(int *c);
#endif

#ifdef NMBD_NAME_REGISTER_SUPPORT
struct netbios_host_table * get_netbios_table(int *c);
#endif
//add by michael to fix the hnap get client status bug at 20080528
struct dhcp_table * get_dhcp_table_expire(int *c);

extern struct ip_lists * find_dns_ip(char *file, char *name, int *c, int type);
extern int find_dns_ip_name(char *file, char *ip, char *name);
	
extern struct detect_wans * detect_protocol(char *wan_face, char *lan_face, char *type);
extern struct detect_wans * detect_pppoe(char *wan_face, char *lan_face, char *type);
//add by michael to fix the CRDC IR-B0010079 and 10080 bug at 20090105
extern struct detect_wans * detect_dhcp(char *wan_face, char *lan_face, char *type);

extern int regmatch( const char* pattern, const char* string );

extern int get_mtd_device(const char *name, int type, char *device);
extern long get_mtd_size(const char *name);
extern int wireless_ready(void);
#define HOME_NETWORK 1
#define GUEST_NETWORK 2
//add by michael to fix the hold lang_pack even do the factory default 20080601
#include <fcntl.h>
extern void remember_lang_value(void);
//end by michael
extern int del_share_file(); 
//add by michael to add the backup/restore dhcp lease file at 20090511
extern int read_dhcp_lease(void);
extern int write_dhcp_lease(void);
//end by michael
#define RESERVED_LEASE_WEIRD 256

#if LINKSYS_MODEL == E200
 enum {	WL = -1,
	DMZ = -2,
	DIAG = 2,
	SES_LED1 = 4,
	RESET_BUTTON = 8,
	SES_BUTTON = 5,
	SES_LED2 = 3,
        DIAG2 = -3,
	USB_LED = -4}; 
#elif ((LINKSYS_MODEL == E1550) || (LINKSYS_MODEL == E155X))
enum {	WL = -1,
	DMZ = -2,
	USB_LED = -3,
	DIAG = 6,
	SES_BUTTON = 9,
	SES_LED1 = 7,
	RESET_BUTTON = 10,
	SES_LED2 = 8,
	DIAG2 = -4};
#elif ((LINKSYS_MODEL == E2500) || (LINKSYS_MODEL == E250X))
enum {	WL = -1,
	DMZ = -2,
	USB_LED = -3,
	DIAG = 6,
	SES_BUTTON = 9,
	SES_LED1 = 7,
	RESET_BUTTON = 10,
	SES_LED2 = 8,
	DIAG2 = -4};
#elif LINKSYS_MODEL == E3200
 enum {	WL = -1,
	DMZ = -2,
	DIAG = 3,
	SES_LED1 = 6, //Reserve now	
	RESET_BUTTON = 5, 
	SES_BUTTON = 8,   
	SES_LED2 = 9, //Reserve now	
       DIAG2 = 2, //Reserve
	USB_LED = 0 //Reserve
	/*USB_LED_CONT1 = 10,
	USB_LED_CONT2 = 11,
	USB_LED1 = 15,
	USB_LED2 = 18*/}; 
#elif ((LINKSYS_MODEL == E4200) || (LINKSYS_MODEL == E420X))
 enum {	WL = -1,
	DMZ = -2,
	DIAG = 1,
	SES_LED1 = 3,	// Orange
	RESET_BUTTON = 6, //wuzh modify 2008-3-3
	SES_BUTTON = 8,   //wuzh modify 2008-3-3
	SES_LED2 = 9,	// White
        DIAG2 = 10,
	USB_LED = 0
	/*USB_LED_CONT1 = 10,
	USB_LED_CONT2 = 11,
	USB_LED1 = 15,
	USB_LED2 = 18*/}; 
#elif LINKSYS_MODEL == E300
#if 0
 enum {	WL = -1,
	DMZ = -2,
	DIAG = 1,
	SES_LED1 = 3,
	RESET_BUTTON = 6,
	SES_BUTTON = 8,
	SES_LED2 = 9,
        DIAG2 = 10,
	USB_LED = 0}; 
#else
 enum {	WL = -1,
	DMZ = -2,
	DIAG = 5,
	SES_LED1 = 0,
	RESET_BUTTON = 6,
	SES_BUTTON = 4,
	SES_LED2 = 3,
        DIAG2 = -1,
	USB_LED = 7}; 
#endif
#else
#error "Unkown model, not setting GPIO enum"
#endif

enum { START_LED,
       STOP_LED,
       MALFUNCTION_LED,
       FLASH_LED };

typedef enum { ACT_IDLE, 
	       ACT_TFTP_UPGRADE, 
	       ACT_WEB_UPGRADE, 
	       ACT_WEBS_UPGRADE, 
	       ACT_SW_RESTORE, 
	       ACT_HW_RESTORE,
	       ACT_ERASE_NVRAM,
	       ACT_NVRAM_COMMIT } ACTION;

enum { UNKNOWN_BOOT = -1,
       PMON_BOOT,
       CFE_BOOT };

enum { BCM4702_CHIP,
       BCM4712_CHIP,
       BCM5325E_CHIP,
       BCM4704_BCM5325F_CHIP,
       BCM5352E_CHIP,
       BCM4712_BCM5325E_CHIP,
       BCM4704_BCM5325F_EWC_CHIP,
       BCM4705_BCM5397_EWC_CHIP,
       BCM4705G_BCM5395S_EWC_CHIP,
       BCM4717_BCM53115S_CHIP,
       BCM4718_BCM53115_CHIP,
       BCM47186_BCM53125_CHIP,
       BCM4718_BCM53115_E3000_CHIP,
       BCM5358U_E1550_CHIP,
       BCM5358U_BCM43236_E2500_CHIP,
       BCM47186_BCM53125_E3200_CHIP,
       BCM4718_BCM53115_E4200_CHIP,
       NO_DEFINE_CHIP };

enum { MODEL_WRT150N,
       MODEL_WRT150NV11,
       MODEL_WRT150NV12,
       MODEL_WRT160N,
       MODEL_WRT310N,
       MODEL_WRT300NV11,
       MODEL_WRT610N,
       MODEL_E300, //Jemmy add for new model E300 2009.9.17
       MODEL_E200,
       MODEL_E1550,
       MODEL_E2500,
       MODEL_E4200,
       MODEL_E3200,
       MODEL_NO_DEFINE };

enum { FIRST, SECOND };

enum { SYSLOG_LOG=1, SYSLOG_DEBUG, CONSOLE_ONLY, LOG_CONSOLE, DEBUG_CONSOLE };

enum { USE_REGEX, FULL_SAME, PARTIAL_SAME };

enum { MTD_CHAR, MTD_BLOCK };

#define ACTION(cmd)	buf_to_file(ACTION_FILE, cmd)

struct dns_lists {
        int num_servers;
        char dns_server[4][16];
};

#define NOT_USING	0
#define USING		1

struct wl_assoc_mac
{
	char mac[18];	// 00:11:22:33:44:55
};

struct arp_table
{
	char ip[16];	// 192.168.1.100
	char mac[18];	// 00:11:22:33:44:55
};

struct dhcp_table
{
	char name[64];
	char ip[16];	// 192.168.1.100
	char mac[18];	// 00:11:22:33:44:55
//add by michael to fix IR-B0013671 connect time did not follow hnap spec in GetConnectedDevice at 20091202
	unsigned long expires;
};

struct host_table
{
	char name[64];
	char ip[16];	// 192.168.1.100
	char mac[18];	// 00:11:22:33:44:55
//add by michael to fix IR-B0013671 connect time did not follow hnap spec in GetConnectedDevice at 20091202
	unsigned long expires;
	int dev;
	int from;
};

#ifdef CES_MDNS_SUPPORT
struct cesmdns_host_table
{
	char name[128];
	char ip[16];	//192.168.1.100
	char mac[18];	//00:01:02:03:04:05
};
#endif

#ifdef NMBD_NAME_REGISTER_SUPPORT
struct netbios_host_table
{
	char name[128];
	char ip[16];	//192.168.1.100
	char mac[18];	//00:01:02:03:04:05
};
#endif

struct ip_lists
{
	char ip[16];
};

enum { DEV_LAN, DEV_WAN, DEV_WL, DEV_NONE };

enum { USE_LAN, USE_WAN};

//michael add the WIRELESS_A to support dual band wireless CRDC-IR-B00100104 at 20090108
enum { WIRELESS_G, WIRELESS_B, WIRELESS_N, WIRELESS_GN,WIRELESS_A};

#define	FROM_ARP_TABLE	0x0001
#define FROM_DHCP_TABLE	0x0002
#define FROM_WL_TABLE	0x0004
#define	FROM_OBA_TABLE	0x0008

struct mtu_lists {
        char	*proto;	/* protocol */
        char	*min;	/* min mtu */
        char	*max;	/* max mtu */
};

struct detect_wans {
	int proto;
	int count;
	char *name;
	char desc[1024];
};

//add by michael to add the white list passthrough at 20080416
struct white_lists {
	char *text;
	char *postfix;
};

#define	PROTO_DHCP	0
#define	PROTO_STATIC	1
#define	PROTO_PPPOE	2
#define	PROTO_PPTP	3
#define	PROTO_L2TP	4
#define	PROTO_HB	5
#define PROTO_EARTHLINK 6
#define	PROTO_ERROR	-1

#define PPP_PSEUDO_IP	"10.64.64.64"
#define PPP_PSEUDO_NM	"255.255.255.255"
#define PPP_PSEUDO_GW	"10.112.112.112"

#define PING_TMP	"/tmp/ping.log"
#define TRACEROUTE_TMP	"/tmp/traceroute.log"
#define MAX_BUF_LEN	254

#define RESOLV_FILE	"/tmp/resolv.conf"
#define HOSTS_FILE	"/tmp/hosts"

#define LOG_FILE	"/var/log/mess"

#define ACTION_FILE	"/tmp/action"

#ifndef MODEL_NUMBER
#error "please set LINKSYS_MODEL & MODEL_NUMBER"
#else
#define STORAGE_INFO_FILE	".storage_info_"MODEL_NUMBER
#endif

#define split(word, wordlist, next, delim) \
	for (next = wordlist, \
	     strncpy(word, next, sizeof(word)), \
	     word[(next=strstr(next, delim)) ? strstr(word, delim) - word : sizeof(word) - 1] = '\0', \
	     next = next ? next + sizeof(delim) - 1 : NULL ; \
	     strlen(word); \
	     next = next ? : "", \
	     strncpy(word, next, sizeof(word)), \
	     word[(next=strstr(next, delim)) ? strstr(word, delim) - word : sizeof(word) - 1] = '\0', \
	     next = next ? next + sizeof(delim) - 1 : NULL)

#define STRUCT_LEN(name)    sizeof(name)/sizeof(name[0])

#define printHEX(str,len) { \
	int i; \
	for (i=0 ; i<len ; i++) { \
		printf("%02X ", (unsigned char)*(str+i)); \
		if(((i+1)%16) == 0) printf("- "); \
		if(((i+1)%32) == 0) printf("\n"); \
	} \
	printf("\n\n"); \
}


#define printASC(str,len) { \
	int i; \
	for (i=0 ; i<len ; i++) { \
		printf("%c", (unsigned char)*(str+i)); \
		if(((i+1)%16) == 0) printf("- "); \
		if(((i+1)%32) == 0) printf("\n"); \
	} \
	printf("\n\n"); \
}

#define SLEEP(time) { \
	int i \
	for(i=0;i<sleep_time;i++) \
		sleep(1); \
}

extern void append_to_file(char *path, char *buf);
char * octal_char_cast(const char *src, char *dest);
char *trim_space_2(char *str);
