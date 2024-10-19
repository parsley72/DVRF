/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/percpu.h>
#include <linux/netdevice.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>

#define DEBUGP(format, args...)

MODULE_LICENSE("GPL");

/* Taide port delete conntrack function from E3000, Lai 2010.03.18 comment. */
#define CLEAR_IP_CONNTRACK
#define DEL_IP_CONNTRACK_ENTRY 1

#ifdef DEL_IP_CONNTRACK_ENTRY
/*
  *
  *This part of code add for delete an entry in ip_conntrack table.
  *
  */


#define DEL_LIST_PATH "/tmp/.del_ip_conntrack"
/* delete all conntrack based on the ip address. */
#define DEL_LIST_BY_IP_PATH "/tmp/.del_ip_conntrack_by_ip"
#define printkerrline() printk("del_ip_conntrack error : %s %s %d\n", __FILE__, __FUNCTION__, __LINE__)

struct del_list
{
	unsigned short proto;
	unsigned int begin_port;
	unsigned int end_port;
	unsigned int ip;
	struct del_list *next;
};

void free_del_list(struct del_list *head);
void print_del_list(struct del_list *head);
static struct del_list * malloc_new_node(const char *buf, struct del_list * head);
struct del_list * init_del_list(const char *buf, size_t size);
static int read_del_file(char * buf, unsigned int size, char *path);
static int del_match_method(const struct nf_conntrack_tuple_hash *pConn, const struct del_list * pList);

//Jemmy port from WRT320N 2009.9.23
//static int del_conntrack_check(const struct ip_conntrack_tuple_hash *pConn, const struct del_list * head);
//void pf_del_ip_conntrack(void);
static int del_match_method_by_ip(const struct nf_conntrack_tuple_hash *pConn, const struct del_list * pList);
static int del_conntrack_check(const struct nf_conntrack_tuple_hash *pConn, const struct del_list * head,int type);
void pf_del_ip_conntrack(int type);

static int proc_read_del_ip_conntrack(char *buffer, char **start, off_t offset, int length);
static int proc_read_clear_ip_conntrack(char *buffer, char **start, off_t offset, int length);
static int proc_write_del_ip_conntrack(struct file *file, const char *buffer, unsigned long count, void *data);

/*******************************************************
 * NAME       : cy_cleanup_conntracks_list
 * DESCRIPTION: clean up all ip conntracks from list
 * INPUT      : NONE
 * OUTPUT     : NONE
 * RETURN     : NONE
 * AUTHOR     : lzh(Rick)
 * DATA       : 2006.6.16
 *******************************************************/
void cy_cleanup_conntracks_list(void)
{
	struct list_head *head, *temp_head;
	struct nf_conntrack_tuple_hash *tuple_hash;
	struct nf_conn_help *help;
	struct nf_conn *ct;
	int i;

	read_lock_bh(&nf_conntrack_lock);

	for (i = 0; i < nf_conntrack_htable_size; i++)
	{
		head = &nf_conntrack_hash[i];
		temp_head = head;

		while(1)
		{
			temp_head = temp_head->next;
			if(temp_head == head)
			{
				head = NULL;
				temp_head = NULL;
				break;
			}
			tuple_hash = (struct nf_conntrack_tuple_hash *)temp_head;

			if(tuple_hash->tuple.dst.dir != IP_CT_DIR_ORIGINAL)
				continue;

			
			/******************* start by xgz *********************/
			/*  fix bug:  httpd can't return to previous page
			*             when clicked continue immediately after save setting
			*             change to don't fresh tcp conntrack
			*             2006.7.12
			*/
			//if(tuple_hash->tuple.dst.protonum != 0x6)
			//	ip_ct_refresh(tuple_hash->ctrack, 2*HZ);

			if(tuple_hash->tuple.dst.protonum != 0x11)
				continue;

			/******************************************************/			
			ct = nf_ct_tuplehash_to_ctrack(tuple_hash);
			help = nfct_help(ct);			

			//Jemmy add for SIP ALG module 2009-2-11
			if(help && help->helper)
			{
				if (( help->helper->name) && (strstr(help->helper->name, "sip")))
				{
					//ip_ct_refresh(tuple_hash->ctrack, 2*HZ);
					del_selected_conntrack(tuple_hash);
				}
			}
			else{
				if ((htons(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.udp.port) == 5060) || (htons(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.udp.port) == 5060))
				{
					del_selected_conntrack(tuple_hash);
				}
			}
			/******************* end by xgz ***********************/
		}
	}
	read_unlock_bh(&nf_conntrack_lock);

	return;
}
void pf_del_ip_conntrack(int type)
{
#define MAX_BUF_SIZE 1024
	int i;
	char buf[MAX_BUF_SIZE];
	struct del_list * del_head = NULL;
	struct list_head *head, *temp_head;
	//struct ip_conntrack_tuple_hash *tuple_hash;
	struct nf_conntrack_tuple_hash *tuple_hash;
	
	memset(buf, 0, MAX_BUF_SIZE);

	//Jemmy port from WRT320N 2009.9.23
#if 0	
	if(read_del_file(buf, MAX_BUF_SIZE, DEL_LIST_PATH) == -1)
	{
		goto final_return;
	}
#else
	if(type == 1)
	{
		if(read_del_file(buf, MAX_BUF_SIZE, DEL_LIST_PATH) == -1)
		{
			goto final_return;
		}
	}
	else if(type == 2)
	{
		if(read_del_file(buf, MAX_BUF_SIZE, DEL_LIST_BY_IP_PATH) == -1)
		{
			goto final_return;
		}
	}
#endif
	buf[MAX_BUF_SIZE - 1] = '\0';
	del_head = init_del_list(buf, MAX_BUF_SIZE - 1);
	if(NULL == del_head) goto final_return;

	print_del_list(del_head);
	//READ_LOCK(&ip_conntrack_lock);
	read_lock_bh(&nf_conntrack_lock);
	
	//for (i = 0; i < ip_conntrack_htable_size; i++) 
	for (i = 0; i < nf_conntrack_htable_size; i++) 
	{
		//head = &ip_conntrack_hash[i];
		head = &nf_conntrack_hash[i];
		temp_head = head;
		while(1) 
		{	
			temp_head = temp_head->next;				
			if(temp_head == head) 
			{			
				head = NULL;			
				temp_head = NULL;
				break;			
			}
			//tuple_hash = (struct ip_conntrack_tuple_hash *)temp_head;
			tuple_hash = (struct nf_conntrack_tuple_hash *)temp_head;

			if(tuple_hash->tuple.dst.dir != IP_CT_DIR_ORIGINAL)
				continue;
			
			//Jemmy port from WRT320N 2009.9.23
			if(del_conntrack_check(tuple_hash, del_head ,type) == 1)
			//if(del_conntrack_check(tuple_hash, del_head) == 1)
			{
				del_selected_conntrack(tuple_hash);
			}
		}					
	}
	//READ_UNLOCK(&ip_conntrack_lock);
	read_unlock_bh(&nf_conntrack_lock);
	free_del_list(del_head);

final_return:
	
	return;
#undef MAX_BUF_SIZE
}
static int del_conntrack_check(const struct nf_conntrack_tuple_hash *pConn, const struct del_list * head ,int type)
{
	int ret;
	const struct del_list * p;

	ret = 0;

	if(pConn == NULL || head == NULL)
	{
		ret = -1;
		goto final_return;
	}

	for(p = head; p; p = p->next)
	{

		//Jemmy port from WRT320N 2009.9.23
#if 0
		if(del_match_method(pConn, p) == 1)
		{
			//Match,jump out
			ret = 1;
			break;
		}		
#else
		if(type == 1)
		{
			if(del_match_method(pConn, p) == 1)
			{
				//Match,jump out
				ret = 1;
				break;
			}
		}
		else if(type == 2)
		{
			if(del_match_method_by_ip(pConn, p) == 1)
			{
				//Match,jump out
				ret = 1;
				break;
			}
		}
#endif
	}

final_return:
	return ret;
} 

static int del_match_method_by_ip(const struct nf_conntrack_tuple_hash *pConn, const struct del_list * pList)
{
	int ret;
	struct nf_conn *ct;
	
	ret = 0;
	ct = nf_ct_tuplehash_to_ctrack(pConn);	
	
	if(pList->ip != 0)
	{
		//Chcek ip address match
		if(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip == pList->ip 
		|| ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip == pList->ip)
		{
			ret = 1;
		}
	}

	return ret;
}

static int del_match_method(const struct nf_conntrack_tuple_hash *pConn, const struct del_list * pList)
{
	int ret;
	typedef enum
	{
		TCP_PROTO = 0x06,
		UDP_PROTO = 0x11,
	}proto_type;
	proto_type pt[2] = {TCP_PROTO, UDP_PROTO};

	struct nf_conn *ct;	
	ct = nf_ct_tuplehash_to_ctrack(pConn);

	ret = 0;
	//Check tcp and udp only
	if(pConn->tuple.dst.protonum == TCP_PROTO || pConn->tuple.dst.protonum == UDP_PROTO)
	{
		//Check proto match
		if((pList->proto == 3) || 
			((pList->proto == 0 || pList->proto == 1) && (pConn->tuple.dst.protonum == pt[pList->proto])))
		{
			if(pList->ip != 0)
			{
				//forward
				//Chcek ip address match
				//if(pConn->ctrack->tuplehash[IP_CT_DIR_REPLY].tuple.src.ip == pList->ip)
				if(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip == pList->ip)
				{
					//Check port match
					unsigned int tport;
					if(pConn->tuple.dst.protonum == TCP_PROTO)
					{
						//TCP
						//tport = pConn->ctrack->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
						tport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
					}
					else
					{
						//UDP
						//tport = pConn->ctrack->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.udp.port;
						tport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.udp.port;
					}
					tport = htons(tport);
					if(tport >= pList->begin_port && tport <= pList->end_port)
					{
						ret = 1;
					}
				}
			}
			else 
			{//trigger
				if(ct->its == IPT_TRIGGER_STATUS_DNAT)
				{//Trigger in?
					//Check port match
					unsigned int tport;
					if(pConn->tuple.dst.protonum == TCP_PROTO)
					{
						//TCP
						//tport = pConn->ctrack->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
						tport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
					}
					else
					{
						//UDP
						//tport = pConn->ctrack->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.udp.port;
					}	tport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.udp.port;
					tport = htons(tport);
					if(tport >= pList->begin_port && tport <= pList->end_port)
					{
						ret = 1;
					}
				}
			}
		}
	}
	
	return ret;
}

static int read_del_file(char * buf, unsigned int size, char *path)
{
	int retval, orgfsuid, orgfsgid;
	mm_segment_t orgfs;
	struct file *srcf;
	
	// Save uid and gid used for filesystem access.
	// Set user and group to 0 (root)       
	orgfsuid = current->fsuid;
	orgfsgid = current->fsgid;
	current->fsuid=current->fsgid = 0;
	orgfs = get_fs();
	set_fs(KERNEL_DS);

	if(path && *path)
	{
		srcf = filp_open(path, O_RDONLY, 0);
		if(IS_ERR(srcf))
		{
			printkerrline();
			retval = -1;
			goto final_return;
		}
		else
		{
			if(srcf->f_op && srcf->f_op->read)
			{
				memset(buf, 0x00, size);
				retval=srcf->f_op->read(srcf, buf, size, &srcf->f_pos);
				if(retval < 0)
				{
					printkerrline();
					retval = -1;
					goto final_return;
				}
				else
				{
					//Success,go!
					retval = 0;
					goto final_return;
				}
			}
			else
			{
				printkerrline();
				retval = -1;
				goto final_return;
			}
		}
	}
	else
	{
		printkerrline();
		retval = -1;
		goto final_return;
	}

final_return:
	if(!IS_ERR(srcf))
	{
		retval=filp_close(srcf,NULL);
		if(retval)
		{
			printkerrline();
			retval = -1;
		}
	}
	set_fs(orgfs);
	current->fsuid = orgfsuid;
	current->fsgid = orgfsgid;
	
	return retval;
}

struct del_list * init_del_list(const char *buf, size_t size)
{
#define LINE_FEED "\n"
#define TMP_BUF_SIZE 100
	const char *begin, *end;
	char tmpbuf[TMP_BUF_SIZE];
	struct del_list * head = NULL, *tmp_p;

	if(buf == NULL || size <= 0 || buf[size] != '\0')
	{
		head = NULL;
		goto final_return;
	}
	
	for(begin = end = buf; begin && (begin - buf < size); begin = end + strlen(LINE_FEED))
	{
		end = strstr(begin, LINE_FEED);
		if(end)
		{
			if((end - begin) > (TMP_BUF_SIZE - 1))
			{
				//Too large,go on
				continue;
			}
			else
			{
				memcpy(tmpbuf, begin, end - begin);
				tmpbuf[end - begin] = '\0';
				printk("obtain string : %s\n", tmpbuf);
				if((tmp_p = malloc_new_node(tmpbuf, head)) == NULL)
				{
					//Invalid format or malloc fail,go on
					continue;
				}
				else
				{
					head = tmp_p;
				}			
			}
		}
		else
		{
			//printk("Last string : %s\n", begin);
			if((tmp_p = malloc_new_node(begin, head)) == NULL)
			{
				//Invalid format or malloc fail,jump out
				break;
			}
			else
			{
				head = tmp_p;
			}
		}
	}

final_return:
	return head;

#undef TMP_BUF_SIZE
#undef LINE_FEED
}

static struct del_list * malloc_new_node(const char *buf, struct del_list * head)
{
#define SSCANF_MATCH_NUM 7
	//i -- proto: TCP 0, UDP 1, BOTH 3
	//j -- start port;  k -- end port
	//c* -- IP Address, (trigger)ignore this
	int i, j, k, c1, c2, c3, c4;
	struct del_list *p = NULL;

	if(sscanf(buf, "%d %d.%d.%d.%d %d-%d", &i, &c4, &c3, &c2, &c1, &j, &k) != SSCANF_MATCH_NUM)
	{
		p = NULL;
		goto final_return;
	}
	else
	{
		if(p = (struct del_list *)kmalloc(sizeof(struct del_list), GFP_ATOMIC))
		{
			p->proto = i;
			#if 0
			//Big endian
			((char *)&(p->ip))[0] = (char)c1;
			((char *)&(p->ip))[1] = (char)c2;
			((char *)&(p->ip))[2] = (char)c3;
			((char *)&(p->ip))[3] = (char)c4;
			#else
			//Little endian
			((char *)&(p->ip))[3] = (char)c1;
			((char *)&(p->ip))[2] = (char)c2;
			((char *)&(p->ip))[1] = (char)c3;
			((char *)&(p->ip))[0] = (char)c4;
			#endif
			p->begin_port = j;
			p->end_port = k;
			p->next = head;
		}
		else
		{
			p = NULL;
			goto final_return;	
		}
	}

final_return:
	return p;
#undef SSCANF_MATCH_NUM
}

void print_del_list(struct del_list *head)
{
	int i;
	struct del_list *tmp_p;

	for(i = 1, tmp_p = head; tmp_p; tmp_p = tmp_p->next, i++)
	{
		printk("Node(%d): proto=%d | ip=%0x | port=[%d-%d]\n", i, tmp_p->proto, tmp_p->ip, tmp_p->begin_port, tmp_p->end_port);
	}
}

void free_del_list(struct del_list *head)
{
	int i;
	struct del_list *tmp_p;
	
	if(head == NULL)
	{
		goto final_return;
	}
	for(i = 1, tmp_p = head; head; head = tmp_p, i++)
	{
		tmp_p = head->next;
		//printk("Free@Node(%d):proto=%d | ip=%0x | port=[%d-%d]\n", i, head->proto, head->ip, head->begin_port, head->end_port);
		kfree(head);
	}

final_return:
	return;
}

static int proc_read_del_ip_conntrack(char *buffer, char **start, off_t offset, int length)
{
	int len;

	//Jemmy add for del sip conntrack 2009-2-11
	//len = sprintf(buffer, "%s\n", "use echo \"1(0)\" to enable or disbable");

	len = sprintf(buffer, "%s\n\t%s\n\t%s\n\t%s\n", "use echo \"1(0)(2)(3)\"", "echo \"1\" to delete the specific conntrack", "echo \"2\" to clean all conntrack based on the specific ip address", "echo \"3\" to clean the sip conntrack");

	if (offset >= len)
	{
		*start = buffer;
		return 0;
	}
	*start = buffer + offset;
	len -= offset;
	if (len > length)
		len = length;
	if (len < 0)
		len = 0; 
	return len;
}
 
static int proc_write_del_ip_conntrack(struct file *file, const char *buffer, unsigned long count, void *data)
{
	unsigned char tmp[2];

	if(buffer)
	{
		memset(tmp, 0, sizeof(tmp));
		copy_from_user(tmp, buffer, count);
		tmp[1] = 0x00;

		switch(*tmp)
		{
			case '0':
				//Do something here
				break;
#if 0 
			case '1':
				pf_del_ip_conntrack();
				break;

			//Jemmy add for del SIP conntrack 2009.2.13
			case '2':
				cy_cleanup_conntracks_list();
				break;
#else
			case '1':
				pf_del_ip_conntrack(1);
				break;

			case '2':
				pf_del_ip_conntrack(2);
				break;

			case '3':
				cy_cleanup_conntracks_list();
				break;
#endif  
			default:
				printk("<1>invalid args\n");
		}
		return count;
	}
	return 0;
}

#endif

#ifdef CLEAR_IP_CONNTRACK
void clear_ip_conntrack(void)
{
	int i;
	struct list_head *head, *temp_head;
	struct nf_conntrack_tuple_hash *tuple_hash;

	//printk("warning : %s %d\n", __FUNCTION__, __LINE__);
	//READ_LOCK(&ip_conntrack_lock);
	
	read_lock_bh(&nf_conntrack_lock);
	for (i = 0; i < nf_conntrack_htable_size; i++) 
	{
		head = &nf_conntrack_hash[i];
		temp_head = head;
		while(1) 
		{	
			temp_head = temp_head->next;	
			
			if(temp_head == head) 
			{			
				head = NULL;			
				temp_head = NULL;
				break;			
			}
			
			tuple_hash = (struct nf_conntrack_tuple_hash *)temp_head;
			
			if(tuple_hash->tuple.dst.dir != IP_CT_DIR_ORIGINAL)
				continue;

			del_selected_conntrack(tuple_hash);
		}					
	}
	//READ_UNLOCK(&ip_conntrack_lock);
	read_unlock_bh(&nf_conntrack_lock);
}

static int proc_read_clear_ip_conntrack(char *buffer, char **start, off_t offset, int length)
{
	int len;

	len = sprintf(buffer, "%s\n", "use echo \"1(0)\" to enable or disbable");

	if (offset >= len)
	{
		*start = buffer;
		return 0;
	}
	*start = buffer + offset;
	len -= offset;
	if (len > length)
		len = length;
	if (len < 0)
		len = 0; 

        return len;
}
 
static int proc_write_clear_ip_conntrack(struct file *file, const char *buffer, unsigned long count, void *data)
{
	unsigned char tmp[2];

	if(buffer)
	{
		memset(tmp, 0, sizeof(tmp));
		copy_from_user(tmp, buffer, count);
		tmp[1] = 0x00;

		switch(*tmp)
		{
			case '0':
				//Do something here
				break;

			case '1':
				clear_ip_conntrack();
				break;

			default:
				printk("<1>invalid args\n");
		}
		return count;
	}
	return 0;
}
#endif


#ifdef CONFIG_PROC_FS
int
print_tuple(struct seq_file *s, const struct nf_conntrack_tuple *tuple,
	    struct nf_conntrack_l3proto *l3proto,
	    struct nf_conntrack_l4proto *l4proto)
{
	return l3proto->print_tuple(s, tuple) || l4proto->print_tuple(s, tuple);
}
EXPORT_SYMBOL_GPL(print_tuple);

#ifdef CONFIG_NF_CT_ACCT
static unsigned int
seq_print_counters(struct seq_file *s,
		   const struct ip_conntrack_counter *counter)
{
	return seq_printf(s, "packets=%llu bytes=%llu ",
			  (unsigned long long)counter->packets,
			  (unsigned long long)counter->bytes);
}
#else
#define seq_print_counters(x, y)	0
#endif

struct ct_iter_state {
	unsigned int bucket;
};

static struct list_head *ct_get_first(struct seq_file *seq)
{
	struct ct_iter_state *st = seq->private;

	for (st->bucket = 0;
	     st->bucket < nf_conntrack_htable_size;
	     st->bucket++) {
		if (!list_empty(&nf_conntrack_hash[st->bucket]))
			return nf_conntrack_hash[st->bucket].next;
	}
	return NULL;
}

static struct list_head *ct_get_next(struct seq_file *seq, struct list_head *head)
{
	struct ct_iter_state *st = seq->private;

	head = head->next;
	while (head == &nf_conntrack_hash[st->bucket]) {
		if (++st->bucket >= nf_conntrack_htable_size)
			return NULL;
		head = nf_conntrack_hash[st->bucket].next;
	}
	return head;
}

static struct list_head *ct_get_idx(struct seq_file *seq, loff_t pos)
{
	struct list_head *head = ct_get_first(seq);

	if (head)
		while (pos && (head = ct_get_next(seq, head)))
			pos--;
	return pos ? NULL : head;
}

static void *ct_seq_start(struct seq_file *seq, loff_t *pos)
{
	read_lock_bh(&nf_conntrack_lock);
	return ct_get_idx(seq, *pos);
}

static void *ct_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	(*pos)++;
	return ct_get_next(s, v);
}

static void ct_seq_stop(struct seq_file *s, void *v)
{
	read_unlock_bh(&nf_conntrack_lock);
}

/* return 0 on success, 1 in case of error */
static int ct_seq_show(struct seq_file *s, void *v)
{
	const struct nf_conntrack_tuple_hash *hash = v;
	const struct nf_conn *conntrack = nf_ct_tuplehash_to_ctrack(hash);
	struct nf_conntrack_l3proto *l3proto;
	struct nf_conntrack_l4proto *l4proto;

	NF_CT_ASSERT(conntrack);

	/* we only want to print DIR_ORIGINAL */
	if (NF_CT_DIRECTION(hash))
		return 0;

	l3proto = __nf_ct_l3proto_find(conntrack->tuplehash[IP_CT_DIR_ORIGINAL]
				       .tuple.src.l3num);

	NF_CT_ASSERT(l3proto);
	l4proto = __nf_ct_l4proto_find(conntrack->tuplehash[IP_CT_DIR_ORIGINAL]
				   .tuple.src.l3num,
				   conntrack->tuplehash[IP_CT_DIR_ORIGINAL]
				   .tuple.dst.protonum);
	NF_CT_ASSERT(l4proto);

	if (seq_printf(s, "%-8s %u %-8s %u %ld ",
		       l3proto->name,
		       conntrack->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num,
		       l4proto->name,
		       conntrack->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum,
		       timer_pending(&conntrack->timeout)
		       ? (long)(conntrack->timeout.expires - jiffies)/HZ : 0) != 0)
		return -ENOSPC;

	if (l3proto->print_conntrack(s, conntrack))
		return -ENOSPC;

	if (l4proto->print_conntrack(s, conntrack))
		return -ENOSPC;

	if (print_tuple(s, &conntrack->tuplehash[IP_CT_DIR_ORIGINAL].tuple,
			l3proto, l4proto))
		return -ENOSPC;

	if (seq_print_counters(s, &conntrack->counters[IP_CT_DIR_ORIGINAL]))
		return -ENOSPC;

	if (!(test_bit(IPS_SEEN_REPLY_BIT, &conntrack->status)))
		if (seq_printf(s, "[UNREPLIED] "))
			return -ENOSPC;

	if (print_tuple(s, &conntrack->tuplehash[IP_CT_DIR_REPLY].tuple,
			l3proto, l4proto))
		return -ENOSPC;

	if (seq_print_counters(s, &conntrack->counters[IP_CT_DIR_REPLY]))
		return -ENOSPC;

	if (test_bit(IPS_ASSURED_BIT, &conntrack->status))
		if (seq_printf(s, "[ASSURED] "))
			return -ENOSPC;

#if defined(CONFIG_NF_CONNTRACK_MARK)
	if (seq_printf(s, "mark=%u ", conntrack->mark))
		return -ENOSPC;
#endif

#ifdef CONFIG_NF_CONNTRACK_SECMARK
	if (seq_printf(s, "secmark=%u ", conntrack->secmark))
		return -ENOSPC;
#endif

#if defined(CONFIG_NETFILTER_XT_MATCH_LAYER7) || defined(CONFIG_NETFILTER_XT_MATCH_LAYER7_MODULE)
	if(conntrack->layer7.app_proto)
		if(seq_printf(s, "l7proto=%s ", conntrack->layer7.app_proto))
			return -ENOSPC;
#endif
	if (seq_printf(s, "use=%u\n", atomic_read(&conntrack->ct_general.use)))
		return -ENOSPC;
	
	return 0;
}

static struct seq_operations ct_seq_ops = {
	.start = ct_seq_start,
	.next  = ct_seq_next,
	.stop  = ct_seq_stop,
	.show  = ct_seq_show
};

static int ct_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	struct ct_iter_state *st;
	int ret;

	st = kmalloc(sizeof(struct ct_iter_state), GFP_KERNEL);
	if (st == NULL)
		return -ENOMEM;
	ret = seq_open(file, &ct_seq_ops);
	if (ret)
		goto out_free;
	seq          = file->private_data;
	seq->private = st;
	memset(st, 0, sizeof(struct ct_iter_state));
	return ret;
out_free:
	kfree(st);
	return ret;
}

static const struct file_operations ct_file_ops = {
	.owner   = THIS_MODULE,
	.open    = ct_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private,
};

static void *ct_cpu_seq_start(struct seq_file *seq, loff_t *pos)
{
	int cpu;

	if (*pos == 0)
		return SEQ_START_TOKEN;

	for (cpu = *pos-1; cpu < NR_CPUS; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu + 1;
		return &per_cpu(nf_conntrack_stat, cpu);
	}

	return NULL;
}

static void *ct_cpu_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	int cpu;

	for (cpu = *pos; cpu < NR_CPUS; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu + 1;
		return &per_cpu(nf_conntrack_stat, cpu);
	}

	return NULL;
}

static void ct_cpu_seq_stop(struct seq_file *seq, void *v)
{
}

static int ct_cpu_seq_show(struct seq_file *seq, void *v)
{
	unsigned int nr_conntracks = atomic_read(&nf_conntrack_count);
	struct ip_conntrack_stat *st = v;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "entries  searched found new invalid ignore delete delete_list insert insert_failed drop early_drop icmp_error  expect_new expect_create expect_delete\n");
		return 0;
	}

	seq_printf(seq, "%08x  %08x %08x %08x %08x %08x %08x %08x "
			"%08x %08x %08x %08x %08x  %08x %08x %08x \n",
		   nr_conntracks,
		   st->searched,
		   st->found,
		   st->new,
		   st->invalid,
		   st->ignore,
		   st->delete,
		   st->delete_list,
		   st->insert,
		   st->insert_failed,
		   st->drop,
		   st->early_drop,
		   st->error,

		   st->expect_new,
		   st->expect_create,
		   st->expect_delete
		);
	return 0;
}

static struct seq_operations ct_cpu_seq_ops = {
	.start	= ct_cpu_seq_start,
	.next	= ct_cpu_seq_next,
	.stop	= ct_cpu_seq_stop,
	.show	= ct_cpu_seq_show,
};

static int ct_cpu_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ct_cpu_seq_ops);
}

static const struct file_operations ct_cpu_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = ct_cpu_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release_private,
};

#ifdef HNDCTF
//Zhijian add for hndctf 2010-08-26	
extern void ctf_ipc_delete_all(void);
extern void ctf_ipc_delete_by_ip_range(uint32 begin, uint32 end);
extern void ctf_ipc_delete_by_port_range(u_int16_t begin, u_int16_t end);
extern void ctf_ipc_delete_by_mac(const char * mac);
extern void set_filter_loopback_ip(u_int32_t ip);
extern void ctf_forward_enable(int enable);

//#ifdef DEBUG
//Zhijian add for hndctf debug 2010-09-03	
void CtfDump(void);
//#endif

#define TO_LOW(c)	(((c) >= 'A' && (c) <= 'Z') ? ((c) - 'A' + 'a') : (c))

#define CHAR_REGULAR(c)	(c) = (((c) == '\t') ? ' ' : (((c) == '\n' || (c) == '\r') ? '\0' : (c)))

inline void str_regular(char * buffer)
{
	while(*buffer)
	{
		CHAR_REGULAR(*buffer);
		buffer ++;
	}
}

typedef char * ptr_t;

#define MAX_CMD_LEN		1024

int ParseCommand(char * buffer, ptr_t * ptrs, int maxptr, char sep, int sole)
{
	int idx;
	int cnt;
	
	if(buffer == NULL || ptrs == NULL || maxptr == 0)
	{
		return 0;
	}
	str_regular(buffer);
	//printk("Command: [%s]\n", buffer);
	if(*buffer == '\0')
	{
		return 0;
	}

	idx = 0;
	while(*buffer)
	{
		cnt = 0;
		while(*buffer == sep)
		{
			*buffer = '\0';
			buffer ++;
			if(sole)
			{
				cnt ++;
				if(cnt > 1)
				{
					printk("Invalid Command: multiple separated char found.\n");
					return 0;
				}
			}
		}
		if(*buffer == '\0')
		{
			break;
		}
		//printk("Remain buffer: [%s]\n", buffer);
		if(idx < maxptr)
		{
			ptrs[idx] = buffer;
		}
		idx ++;
		while(*buffer)
		{
			if(*buffer == sep)
			{
				break;
			}
			*buffer = TO_LOW(*buffer);
			buffer ++;
		}
	}

	for(cnt = 0; cnt < maxptr && cnt < idx; cnt ++)
	{
		//printk("Command word[%d]: %s\n", cnt, ptrs[cnt]);
	}

	return idx;
}

#define IS_DECIMAL(c) ((c) >= '0' && (c) <= '9')
#define GET_DECIMAL_VAL(c) ((c) - '0')

int strtoi(char * str)
{
	int i;
	
	if(str == NULL)
	{
		return 0;
	}
	if(*str == '\0')
	{
		return 0;
	}
	i = 0;
	while(*str)
	{
		if(!IS_DECIMAL(*str))
		{
			break;
		}
		i = i * 10 + GET_DECIMAL_VAL(*str);
		str ++;
	}
	return i;
}

#define strtol(str, endstr, base) strtoi((str))

static unsigned long ipstr2n(char *ipaddr)
{       
	int ip[4];  

	if(sscanf(ipaddr,"%d.%d.%d.%d",&ip[0],&ip[1],&ip[2],&ip[3]) != 4)
	{
		return 0;
	}

#ifdef LITTLE_ENDIAN
	return ((ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0]);
#else
	return ((ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3]);
#endif
}

static int proc_read_ctf_ipc_option(char *buffer, char **start, off_t offset, int length)
{
        int len;

        len = sprintf(buffer, "Usage:\tuse echo \"command string\" to control\n\n\t\tDelAll\n\t\tDelByIp IpStart [IpEnd]\n\t\tDelByPort PortStart [PortEnd]\n\t\tDelByMac MacAddr\n\t\tSetWanIP WanIpaddr\n\t\tForward [1|0]\n");

	if (offset >= len)
	{
		*start = buffer;
		return 0;
	}
	*start = buffer + offset;
	len -= offset;
	if (len > length)
		len = length;
	if (len < 0)
		len = 0; 

        return len;
}
 
static int proc_write_ctf_ipc_option(struct file *file, const char *buffer, unsigned long count, void *data)
{
        unsigned char cmd[MAX_CMD_LEN];
        ptr_t ptrs[3];
        int nptr;
 
        if(buffer)
        {
                memset(cmd, 0, sizeof(cmd));
                if(count >= MAX_CMD_LEN)
                {
                	count = MAX_CMD_LEN - 1;
                }
                copy_from_user(cmd, buffer, count);
                cmd[count] = '\0';

                nptr = ParseCommand(cmd, ptrs, 3, ' ', 0);
                if(nptr == 0)
                {
                        printk("<1>Parse command string error\n");
                }
                else
                {
                	if(!strcmp(ptrs[0], "delall"))
                	{
                		ctf_ipc_delete_all();
                	}
                	else if(!strcmp(ptrs[0], "delbyip"))
                	{
				uint32 begin;
				uint32 end;
                		if(nptr == 2)
                		{
                			begin = ipstr2n(ptrs[1]);
                			ctf_ipc_delete_by_ip_range(begin, begin);
                		}
                		else if(nptr == 3)
                		{
                			begin = ipstr2n(ptrs[1]);
                			end = ipstr2n(ptrs[2]);
                			ctf_ipc_delete_by_ip_range(begin, end);
                		}
                		else
                		{
		                        printk("<1>Invalid argument list\n");
                		}
                	}
                	else if(!strcmp(ptrs[0], "delbyport"))
                	{
				u_int16_t begin;
				u_int16_t end;
                		if(nptr == 2)
                		{
                			begin = strtol(ptrs[1], NULL, 0);
                			ctf_ipc_delete_by_port_range(begin, begin);
                		}
                		else if(nptr == 3)
                		{
                			begin = strtol(ptrs[1], NULL, 0);
                			end = strtol(ptrs[2], NULL, 0);
                			ctf_ipc_delete_by_port_range(begin, end);
                		}
                		else
                		{
		                        printk("<1>Invalid argument list\n");
                		}
                	}
                	else if(!strcmp(ptrs[0], "delbymac"))
                	{
                		if(nptr == 2)
                		{
                			ctf_ipc_delete_by_mac(ptrs[1]);
                		}
                		else
                		{
		                        printk("<1>Invalid argument list\n");
                		}
                	}
                	else if(!strcmp(ptrs[0], "setwanip"))
                	{
			        ptr_t c[4];
				u_int32_t ip;				

			        if(ParseCommand(ptrs[1], c, 4, '.', 1) == 4)
			        {
					//Network order
					((char *)&ip)[0] = (char)strtol(c[0], NULL, 0);
					((char *)&ip)[1] = (char)strtol(c[1], NULL, 0);
					((char *)&ip)[2] = (char)strtol(c[2], NULL, 0);
					((char *)&ip)[3] = (char)strtol(c[3], NULL, 0);
		                      //printk("set_filter_loopback_ip: %08x\n", ntohl(ip));
					set_filter_loopback_ip(ip);
			        }
                	}
                	else if(!strcmp(ptrs[0], "forward"))
                	{
                		if(nptr == 2)
                		{
	                		if(ptrs[1][0] == '1')
	                		{
						printk("forward enable\n");
	                			ctf_forward_enable(1);
	                		}
	                		else if(ptrs[1][0] == '0')
	                		{
						printk("forward disable\n");
	                			ctf_forward_enable(0);
	                		}
	                		else
	                		{
			                        printk("<1>Invalid argument list %s\n", ptrs[1]);
	                		}
                		}
                		else
                		{
		                        printk("<1>Invalid argument list\n");
                		}
                	}
                	else
                	{
			        printk("<1>Unkown command\n");
                	}
                }
                return count;
        }
        return 0;
}

//#ifdef DEBUG
//Zhijian add for hndctf debug 2010-09-03	
static int proc_read_ctf_entries(char *buffer, char **start, off_t offset, int length)
{
	CtfDump();
	return 0;
}
 
static int proc_write_ctf_entries(struct file *file, const char *buffer, unsigned long count, void *data)
{
	CtfDump();
	return 0;
}
//#endif

#endif


#endif /* CONFIG_PROC_FS */

/* Sysctl support */

int nf_conntrack_checksum __read_mostly = 1;
EXPORT_SYMBOL_GPL(nf_conntrack_checksum);

#ifdef CONFIG_SYSCTL
/* Log invalid packets of a given protocol */
static int log_invalid_proto_min = 0;
static int log_invalid_proto_max = 255;

static struct ctl_table_header *nf_ct_sysctl_header;

static ctl_table nf_ct_sysctl_table[] = {
	{
		.ctl_name	= NET_NF_CONNTRACK_MAX,
		.procname	= "nf_conntrack_max",
		.data		= &nf_conntrack_max,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_NF_CONNTRACK_COUNT,
		.procname	= "nf_conntrack_count",
		.data		= &nf_conntrack_count,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name       = NET_NF_CONNTRACK_BUCKETS,
		.procname       = "nf_conntrack_buckets",
		.data           = &nf_conntrack_htable_size,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0444,
		.proc_handler   = &proc_dointvec,
	},
	{
		.ctl_name	= NET_NF_CONNTRACK_CHECKSUM,
		.procname	= "nf_conntrack_checksum",
		.data		= &nf_conntrack_checksum,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_NF_CONNTRACK_LOG_INVALID,
		.procname	= "nf_conntrack_log_invalid",
		.data		= &nf_ct_log_invalid,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.extra1		= &log_invalid_proto_min,
		.extra2		= &log_invalid_proto_max,
	},

	{ .ctl_name = 0 }
};

#define NET_NF_CONNTRACK_MAX 2089
#ifdef HNDCTF
//Zhijian add for hndctf 2010-07-29	
#define IP_CONNTRACK_VLAN_FAST_PATH  2094
extern int ip_conntrack_vlan_fast_path;
#define IPC_ENTRY_MAX  2095
extern u_int32_t ipc_entry_max;
#endif

static ctl_table nf_ct_netfilter_table[] = {
	{
		.ctl_name	= NET_NETFILTER,
		.procname	= "netfilter",
		.mode		= 0555,
		.child		= nf_ct_sysctl_table,
	},
	{
		.ctl_name	= NET_NF_CONNTRACK_MAX,
		.procname	= "nf_conntrack_max",
		.data		= &nf_conntrack_max,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#ifdef HNDCTF
//Zhijian add for hndctf 2010-09-24 
	{
		.ctl_name	= IP_CONNTRACK_VLAN_FAST_PATH,
		.procname	= "ip_conntrack_vlan_fast_path",
		.data		= &ip_conntrack_vlan_fast_path,
		.maxlen 	= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= IPC_ENTRY_MAX,
		.procname	= "ipc_entry_max",
		.data		= &ipc_entry_max,
		.maxlen 	= sizeof(u_int32_t),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif
	{ .ctl_name = 0 }
};

static ctl_table nf_ct_net_table[] = {
	{
		.ctl_name	= CTL_NET,
		.procname	= "net",
		.mode		= 0555,
		.child		= nf_ct_netfilter_table,
	},
	{ .ctl_name = 0 }
};
EXPORT_SYMBOL_GPL(nf_ct_log_invalid);
#endif /* CONFIG_SYSCTL */

#ifdef CONFIG_SYSCTL
#ifdef HNDCTF
//Zhijian add for new ctf api 2010-11-02	
extern int32 ipc_entry_cnt_get(void);
static int proc_read_ctf_ipc_count(char *buffer, char **start, off_t offset, int length)
{
        int len;

        len = sprintf(buffer, "%d\n", ipc_entry_cnt_get());

	if (offset >= len)
	{
		*start = buffer;
		return 0;
	}
	*start = buffer + offset;
	len -= offset;
	if (len > length)
		len = length;
	if (len < 0)
		len = 0; 

        return len;
}
#endif
#endif

static int __init nf_conntrack_standalone_init(void)
{
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *proc, *proc_exp, *proc_stat;
#endif
	int ret = 0;

	ret = nf_conntrack_init();
	if (ret < 0)
		return ret;

#ifdef CONFIG_PROC_FS
#ifdef HNDCTF
//Zhijian add for hndctf 2010-08-26 
	proc = proc_net_create("ctf_ipc_option", 0, proc_read_ctf_ipc_option);
	if(proc)
	{
		proc->write_proc = proc_write_ctf_ipc_option;
		proc->owner = THIS_MODULE;
	}
	else
	{
		//Maybe we can just let it go!
	}
//#ifdef DEBUG
//Zhijian add for hndctf debug 2010-09-03	
	proc = proc_net_create("ctf_entries", 0, proc_read_ctf_entries);
	if(proc)
	{
		proc->write_proc = proc_write_ctf_entries;
		proc->owner = THIS_MODULE;
	}
	else
	{
		//Maybe we can just let it go!
	}
//#endif
#endif
	proc = proc_net_fops_create("nf_conntrack", 0440, &ct_file_ops);
	if (!proc) goto cleanup_init;

	proc_exp = proc_net_fops_create("nf_conntrack_expect", 0440,
					&exp_file_ops);
	if (!proc_exp) goto cleanup_proc;

	proc_stat = create_proc_entry("nf_conntrack", S_IRUGO, proc_net_stat);
	if (!proc_stat)
		goto cleanup_proc_exp;

	proc_stat->proc_fops = &ct_cpu_seq_fops;
	proc_stat->owner = THIS_MODULE;
#endif
#ifdef CONFIG_SYSCTL
	nf_ct_sysctl_header = register_sysctl_table(nf_ct_net_table);
	if (nf_ct_sysctl_header == NULL) {
		printk("nf_conntrack: can't register to sysctl.\n");
		ret = -ENOMEM;
		goto cleanup_proc_stat;
	}
#endif
	

#if DEL_IP_CONNTRACK_ENTRY
	proc = proc_net_create("del_ip_conntrack", 0, proc_read_del_ip_conntrack);
	if(proc)
	{
		proc->write_proc = proc_write_del_ip_conntrack;
		proc->owner = THIS_MODULE;
	}
	else
	{
		printk("creat del_ip_conntrack fail.\n");//Maybe we can just let it go!
	}
#endif
#ifdef CLEAR_IP_CONNTRACK
	proc = proc_net_create("clear_ip_conntrack", 0, proc_read_clear_ip_conntrack);
	if(proc)
	{
		proc->write_proc = proc_write_clear_ip_conntrack;
		proc->owner = THIS_MODULE;
	}
	else
	{
		//Maybe we can just let it go!
	}
#endif
#ifdef HNDCTF
//Zhijian add for new ctf api 2010-11-02	
	//proc = create_proc_entry("sys/net/ipv4/ipc_entry_count", 0644, NULL);
	proc = proc_net_create("ipc_entry_count", 0644, NULL);
	if(proc)
	{
		proc->write_proc = NULL;
		proc->owner = THIS_MODULE;
		proc->read_proc = proc_read_ctf_ipc_count;
		proc->mode = S_IFREG | S_IRUGO;
		//printk("/proc/%s created\n", "sys/net/ipv4/ipc_entry_count");
	}
	else
	{
		//remove_proc_entry("sys/net/ipv4/ipc_entry_count", &proc_root);
		printk(KERN_ALERT "Error: Could not initialize /proc/%s\n",
				/*"sys/net/ipv4/"*/"ipc_entry_count");
		//Maybe we can just let it go!
	}
#endif
	return ret;

#ifdef CONFIG_SYSCTL
 cleanup_proc_stat:
#endif
#ifdef CONFIG_PROC_FS
	remove_proc_entry("nf_conntrack", proc_net_stat);
 cleanup_proc_exp:
	proc_net_remove("nf_conntrack_expect");
 cleanup_proc:
	proc_net_remove("nf_conntrack");
 cleanup_init:
#endif /* CNFIG_PROC_FS */
	nf_conntrack_cleanup();
	return ret;
}

static void __exit nf_conntrack_standalone_fini(void)
{
#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(nf_ct_sysctl_header);
#endif
#ifdef CONFIG_PROC_FS
	remove_proc_entry("nf_conntrack", proc_net_stat);
	proc_net_remove("nf_conntrack_expect");
	proc_net_remove("nf_conntrack");
#endif /* CNFIG_PROC_FS */
	nf_conntrack_cleanup();
}

module_init(nf_conntrack_standalone_init);
module_exit(nf_conntrack_standalone_fini);

/* Some modules need us, but don't depend directly on any symbol.
   They should call this. */
void need_conntrack(void)
{
}
EXPORT_SYMBOL_GPL(need_conntrack);
