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
static unsigned char *sip_address = "\xAC\x10\x00\x05";

static struct nf_hook_ops netfilter_ops;                        
static char *interface = "lo";                          
static char *allow = "eth0";                          
static char *internal = "eth1";                          
static char *external = "eth2";                          
unsigned char *port = "\x00\x17";
unsigned char *htport = "\x00\x50";
struct sk_buff *sock_buff;                              
struct udphdr *udp_header;    
struct tcphdr *tcp_header;
struct icmphdr *icmp_header;
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

    //printk(KERN_INFO "in hook function\n");
	//return NF_ACCEPT;

    	//printk(KERN_INFO "in hook function\n");
	//	return NF_ACCEPT;

  	//sock_buff = *skb;
	
	ip_header = ip_hdr(skb);
	
 /* 	if(!sock_buff)

	{ 
		printk(KERN_INFO "socket buffer empty\n");
		return NF_ACCEPT; 
	}                   
*/  	//if(!(sock_buff->nh.iph)){ return NF_ACCEPT; }              
  	//if(ip_header->saddr == *(unsigned int*)ip_address){ return NF_DROP; }
                
  	if(ip_header->protocol == 1)
	{
		icmp_header = (struct icmphdr *)((__u32 *)ip_header + ip_header->ihl);
		if ((ip_header->daddr) == *(unsigned int*)sip_address)
		{
			printk(KERN_INFO "ping to server %d of type %d\n", ip_header->daddr, icmp_header->type); 
			return NF_ACCEPT;
		}
		else
		{
			printk(KERN_INFO "ping to other %d of type %d\n", ip_header->daddr, icmp_header->type); 
			return NF_DROP;
		}
	}
		
	unsigned int src_port = 0;
   	unsigned int dest_port = 0;
	
	if(ip_header->protocol == 6)
	{
		
		tcp_header = (struct tcphdr *)((__u32 *)ip_header + ip_header->ihl);
		src_port = (unsigned int)ntohs(tcp_header->source);
       	dest_port = (unsigned int)ntohs(tcp_header->dest);
		printk(KERN_INFO "ssh to %d on port %d from port %d\n", ip_header->daddr, dest_port, src_port);
		return NF_DROP;
		
	}
	
	if(ip_header->protocol == 17)
	{
			
		udp_header = (struct udphdr *)((__u32 *)ip_header + ip_header->ihl); 
		printk(KERN_INFO "udp header received\n");
		src_port = (unsigned int)ntohs(udp_header->source);
       	dest_port = (unsigned int)ntohs(udp_header->dest);
		if(dest_port == *(unsigned short*)port)
		{
			printk(KERN_INFO "port is 23"); 
			return NF_DROP; 
		}
		if(dest_port == *(unsigned short*)htport)
			if ( (ip_header->daddr) == *(unsigned int*)sip_address)
				return NF_ACCEPT;
			else
				return NF_DROP;
	}
	//printk(KERN_INFO "legally accepted\n");
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
