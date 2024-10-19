#ifndef _IP6T_WEBSTR_H
#define _IP6T_WEBSTR_H

#define BM_MAX_NLEN 256
#define BM_MAX_HLEN 1024

#define BLK_JAVA		0x01
#define BLK_ACTIVE		0x02
#define BLK_COOKIE		0x04
#define BLK_PROXY		0x08

typedef char *(*proc_ip6t_search) (char *, char *, int, int);

struct ip6t_webstr_info {
    char string[BM_MAX_NLEN];
    u_int16_t invert;
    u_int16_t len;
    u_int8_t type;
};

enum ip6t_webstr_type
{
    IP6T_WEBSTR_HOST,
    IP6T_WEBSTR_URL,
    IP6T_WEBSTR_CONTENT,
    IP6T_WEBSTR_HTTP_INIT,
    IP6T_WEBSTR_HTTP_WLIST,
    IP6T_WEBSTR_HTTPS_WLIST
};

#endif /* _IP6T_WEBSTR_H */
