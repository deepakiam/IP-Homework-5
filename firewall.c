#define __KERNEL__
#define MODULE
#include <linux/ip.h>             
#include <linux/netdevice.h>      
#include <linux/skbuff.h>         
#include <linux/udp.h>          
#include <linux/tcp.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/init.h>
#include <asm-generic/types.h>
#include <net/checksum.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("linux-simple-firewall");
MODULE_AUTHOR("dnair");

struct iphdr *ip_header;	//ip header pointer
static unsigned char *ip_address = "\xAC\x10\x01\x01"; 

static struct nf_hook_ops netfilter_ops;                        
static char *interface = "lo";                          
static char *allow = "eth0";                          
static char *internal = "eth1";                          
static char *external = "eth2";                          
unsigned char *port = "\x00\x17";                       
struct sk_buff *sock_buff;                              
struct udphdr *udp_header;                              
unsigned int main_hook(unsigned int hooknum,
                  struct sk_buff *skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{
	//printk(KERN_INFO "in hook function\n");
	if (in) {
	if(strcmp(in->name,allow) == 0){ return NF_ACCEPT; }
	//if(strcmp(in->name,internal) == 0){ return NF_ACCEPT; }
  	if(strcmp(in->name,interface) == 0)
	{ 
	  return NF_DROP; 
	}    
    printk(KERN_INFO "in hook function\n");
	//	return NF_ACCEPT;
  	sock_buff = *skb;
	
	ip_header = ip_hdr(skb);
	//ip_header = (struct iphdr *)skb_network_header(sock_buff);	//extract ip_header
		printk(KERN_INFO "extracted header\n");
			return NF_ACCEPT;
  	if(!sock_buff)
	{ 
		return NF_ACCEPT; 
	}                   
  	//if(!(sock_buff->nh.iph)){ return NF_ACCEPT; }              
  	//if(sock_buff->nh.iph->saddr == *(unsigned int*)ip_address){ return NF_DROP; }
                
  	printk(KERN_INFO "a legit packet\n");
	//if(sock_buff->nh.iph->protocol != 17)
	if(ip_header->protocol != 17)
	{ 
		return NF_ACCEPT; 
	}                 
	//udp_header = (struct udphdr *)(sock_buff->data + (sock_buff->nh.iph->ihl *4)); 
	udp_header = (struct udphdr *)(sock_buff->data + (ip_header->ihl *4)); 
	if((udp_header->dest) == *(unsigned short*)port)
	{ 
		return NF_ACCEPT;//return NF_DROP; 
	}
		return NF_ACCEPT;
	}
	else
		return NF_ACCEPT;
}

int init_module()
{
		printk(KERN_INFO "initialize kernel module\n");
        netfilter_ops.hook              =       main_hook;
        netfilter_ops.pf                =       PF_INET;        
        netfilter_ops.hooknum           =       0;
        netfilter_ops.priority          =       NF_IP_PRI_FIRST;
        nf_register_hook(&netfilter_ops);
        
return 0;
}
void cleanup_module() 
{
	nf_unregister_hook(&netfilter_ops); 
}
