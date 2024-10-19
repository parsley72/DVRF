#ifndef _LINUX_CONFIG_H
#define _LINUX_CONFIG_H

#ifdef CONFIG_IPV6
#undef CONFIG_IPV6
#endif

#ifdef CONFIG_PPPOE
#undef CONFIG_PPPOE
#endif

/*-- wuzh add for EGHN support 2008-4-18 --*/
#include "../../../../cy_conf.h"

#ifdef CONFIG_IPV6
#undef CONFIG_IPV6
#endif

#ifdef CONFIG_PPPOE
#undef CONFIG_PPPOE
#endif

#include <linux/autoconf.h>

#ifndef EGHN_SUPPORT
#undef CONFIG_NET_CLS_TCINDEX
#endif
/*-- wuzh 2008-4-18 --*/

#endif
