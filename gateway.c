#define __KERNEL__
#define MODULE
#include <linux/ip.h>             
#include <linux/netdevice.h>      
#include <linux/skbuff.h>         
#include <linux/udp.h>          

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/init.h>
#include <asm-generic/types.h>
#include <net/checksum.h>


static struct nf_hook_ops nfho;         
struct sk_buff *sock_buff;	//current buffer
struct iphdr *ip_header;	//ip header pointer
static unsigned char *ip_address = "\xAC\x10\x01\x01"; 

char * parseIPV4(char* ipAddress, int arr[4]);
int isInRange(char *start, char *end, char *check);
int init_module();
void cleanup_module();

unsigned int hook_setpriority(unsigned int hooknum, struct sk_buff **skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	
	sock_buff = *skb;
	unsigned short ip_len;
	struct sockaddr_in src_addr;
	struct udphdr *udp_header;
	
	//extract header info on incoming pkt
	
	ip_header = (struct iphdr *)skb_network_header(sock_buff);	//extract ip_header
	
	ip_len = ip_header->ihl * 4;				//no. of words of IP header
	
	unsigned short prot = ip_header->protocol;
	
	char *loopback = "lo";
	
	/*if(strcmp(ip_header->name,loopback) == 0)
	 { 
		 return NF_DROP; 
	 }*/
	
	//if(!sock_buff){ return NF_ACCEPT; }            //check       
  	//if(!(sock_buff->nh.iph)){ return NF_ACCEPT; }  //check
	
	memset(&src_addr, 0, sizeof(src_addr));
	//src_addr.sin_addr.s_addr = ip_header->saddr;			        //source ip address
	
	unsigned int sip = (unsigned int)ip_header->saddr;
	unsigned int dip = (unsigned int)ip_header->daddr;
	unsigned int prot = (unsigned int)ip_header->protocol;
	unsigned int sport = 0;
	unsigned int dport = 0;
	
	if (prot==17) {
       udp_header = (struct udphdr *)skb_transport_header(skb);
       sport = (unsigned int)ntohs(udp_header->source);
       dport = (unsigned int)ntohs(udp_header->dest);
   } else if (ip_header->protocol == 6) {
       tcp_header = (struct tcphdr *)skb_transport_header(skb);
       sport = (unsigned int)ntohs(tcp_header->source);
       dport = (unsigned int)ntohs(tcp_header->dest);
   }
	
	printk(KERN_INFO "OUT packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; proto: %u\n", src_ip, src_port, dest_ip, dest_port, ip_header->protocol);
	
	//determine the class of packet from source
	char incoming_addr[16] ;
	char server_addr[16] = "172.16.0.5";
//	sprintf(incoming_addr,"%s",inet_ntoa(src_addr.sin_addr));

	
	if (sip == ip_address)
	
	if(isInRange("172.16.0.0","172.16.0.10",incoming_addr) == 1)			//Class A  Bit format : 000 001 XX
	{
		return NF_ACCEPT;
			
	}else 
	{
		if( strcmp(incoming_addr, server_addr) == 0)		//Class C  Bit format : 000 111 XX
		{
//			sprintf("to be dropped");
//			return NF_DROP;
			return NF_ACCEPT;
		}
	}
	
	unsigned char *port = "\x00\x50"; 
	
	//udp_header = (struct udphdr *)(sock_buff->data + (sock_buff->nh.iph->ihl *4)); 
	//if((udp_header->dest) == *(unsigned short*)port){ 
	//sprintf("to be dropped");
	//return NF_DROP; 
	//return NF_ACCEPT;
	//}
	

	return NF_ACCEPT;
	
}


/*Function to check if *check lies within the IPv4 address range of *start and *end inclusive*/

int isInRange(char *start, char *end, char *check)	
{
	int address_array[3][4];
	int a=0;
	int b=0;
	
	parseIPV4(start,address_array[0]);	
	parseIPV4(end,address_array[1]);
	parseIPV4(check,address_array[2]);

	for(b=0;b<4;b++)
		if(((address_array[0][b] <= address_array[2][b]) && (address_array[2][b] <= address_array[1][b])) == 0) return 0;

	return 1;

}

/*Function to separate octets of IPv4 address*/

char * parseIPV4(char* ipAddress, int arr[4]) {
 	
	sscanf(ipAddress, "%d.%d.%d.%d", &arr[3], &arr[2], &arr[1], &arr[0]);
	return arr;	
}



int init_module()
{
  nfho.hook = hook_setpriority;
  nfho.hooknum = 2;		//call when decsion is made for forwarding
  nfho.pf = PF_INET;                           		//IPV4 pkts
  nfho.priority = NF_IP_PRI_FIRST;             	//set to highest priority
  nf_register_hook(&nfho);                     	//register hook

  return 0;                                    //return 0 for success
}


void cleanup_module()
{
  nf_unregister_hook(&nfho);                     //unregister
}

