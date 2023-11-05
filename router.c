#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct route_table_entry next_hop_binary_search(int *este_null, struct route_table_entry *rtable, int rtable_size,  uint32_t ip_addr) {
	int start = 0;
	int end = rtable_size - 1;
	struct route_table_entry temp;
	memset(&temp, 0, sizeof(struct route_table_entry));
	while (start <= end) {
		int mid = (start + end)/2;
		if((ip_addr & ntohl(rtable[mid].mask)) == ntohl(rtable[mid].prefix)){
			temp = rtable[mid];
			*este_null = 1; // stiu ca temp nu mai are zero uri
			end = mid - 1;
		}
		else if((ip_addr & ntohl(rtable[mid].mask)) < ntohl(rtable[mid].prefix))
			start = mid + 1;
		else 
			end = mid - 1;
	}
	return temp;
}

int compare_binary(const void *a, const void *b) {
	struct route_table_entry *rte1 = (struct route_table_entry *)a;
	struct route_table_entry *rte2 = (struct route_table_entry *)b;
	if ( ntohl(rte1->mask) != ntohl(rte2->mask))
		return (int)(ntohl(rte2->mask) - ntohl(rte1->mask));
	else {
		return (int)(ntohl(rte2->prefix) - ntohl(rte1->prefix));
	}
}


struct arp_entry search_mac_by_ip(struct arp_entry *arp_table, uint32_t ip) {
	int i = 0;
	while(1) {
		if(arp_table[i].ip == ip) 
			return arp_table[i];
		i++;
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry rtable[100000];
	int rtable_size = read_rtable(argv[1], rtable);
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), compare_binary);

	struct arp_entry arp_table[100];
	parse_arp_table("arp_table.txt", arp_table);

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		int ethernet_type = ntohs(eth_hdr->ether_type);
		
		// PART 1 - IPV4
		if(ntohs(eth_hdr->ether_type) == 0x0800) {
			
			struct iphdr *ip_hdr = (struct iphdr*) (buf + sizeof(struct ether_header));
	
			// verificare1: pachetul este pt noi?
			// destinatie == ip interfata 
			// inet_addr = fct transforma din string in ipv4
			if(inet_addr(get_interface_ip(interface)) == ip_hdr->daddr) {
				// verificare2: mesaj tip ICMP?
				if(ip_hdr->protocol == 	IPPROTO_ICMP){

					// icmp hdr
					struct icmphdr *icmp_hdr = (struct icmphdr*) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
					icmp_hdr->type = 0;
					icmp_hdr->code = 0;
					icmp_hdr->checksum = 0;
					icmp_hdr->checksum = checksum((uint16_t*)icmp_hdr, sizeof(struct icmphdr));
					
					// ip hdr
					uint32_t aux  = ip_hdr->saddr;
					ip_hdr->saddr = ip_hdr->daddr;
					ip_hdr->daddr = aux;
					ip_hdr->ttl = 64;
					ip_hdr->check = 0;
					ip_hdr->check = checksum((uint16_t*)ip_hdr, sizeof(struct iphdr));

					// eth hdr				
					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
					get_interface_mac(interface, eth_hdr->ether_shost);

					send_to_link(interface, buf, len);
				}
				continue;
			}


			uint16_t check_sum = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			uint16_t new_sum = checksum((uint16_t*)ip_hdr, sizeof(struct iphdr));
			if(check_sum != new_sum) {
				continue;
			}

			ip_hdr->ttl--;
			if(ip_hdr->ttl <= 0) {
				//trb sa trimit inapoi la emitator un mesaj icmp

				// TIME EXCEEDED ICMP
				char *ttl = (char *)calloc(sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), 1);
				struct ether_header* eth_ttl = (struct ether_header *) ttl;
				struct iphdr *ip_ttl = (struct iphdr*) (ttl + sizeof(struct ether_header));
				struct icmphdr *icmp_ttl = (struct icmphdr*)(ttl + sizeof(struct ether_header) + sizeof(struct iphdr));

				//icmp hdr
				icmp_ttl->type = 11;
				icmp_ttl->code = 0;
				icmp_ttl->checksum = 0;
				icmp_ttl->checksum = checksum((uint16_t *)icmp_ttl, sizeof(struct icmphdr));

				//ip hdr
				ip_ttl->saddr = ip_hdr->daddr;
				ip_ttl->daddr = ip_hdr->saddr;
				ip_ttl->protocol = IPPROTO_ICMP;
				ip_ttl->tos = 0;
				ip_ttl->version = 4;
				ip_ttl->ihl = 5;
				ip_ttl->ttl = 64;
				ip_ttl->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				ip_ttl->id = htons(1);
				ip_ttl->frag_off = htons(0);
				ip_ttl->check = checksum((uint16_t *)ip_ttl, sizeof(struct icmphdr));
				
				//eth hdr
				eth_ttl->ether_type = htons(0x0800);
				memcpy(eth_ttl->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
				get_interface_mac(interface, eth_ttl->ether_shost);

				
				send_to_link(interface, ttl, sizeof(struct ether_header) + sizeof(struct iphdr) +sizeof(struct icmphdr));
				

				continue;
			}

			int este_null = 0;
			struct route_table_entry next = next_hop_binary_search(&este_null, rtable, rtable_size, ntohl(ip_hdr->daddr));
						
			// ICMP DEST UNREACHABLE
			if(este_null == 0) { 

				//are doar zerouri
				char* dest = (char*) calloc(sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), 1);
				struct ether_header *eth_dest = (struct ether_header *) dest;
				struct iphdr *ip_dest = (struct iphdr *) (dest + sizeof(struct ether_header));
				struct icmphdr *icmp_hdr_dest = (struct icmphdr*) (dest + sizeof(struct ether_header) + sizeof(struct iphdr));

				// icmp hdr
				icmp_hdr_dest->type = 3;
				icmp_hdr_dest->code = 0;
				icmp_hdr_dest->checksum = 0;
				icmp_hdr_dest->checksum = checksum((uint16_t *)icmp_hdr_dest, sizeof(struct icmphdr));

				// ip hdr
				uint32_t aux  = ip_dest->saddr;
				ip_dest->saddr = ip_hdr->daddr;
				ip_dest->daddr = aux;
				ip_dest->version = 4;
				ip_dest->ihl = 5;
				ip_dest->tos = 0;
				ip_dest->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				ip_dest->id = htons(1);
				ip_dest->frag_off = htons(0);
				ip_dest->ttl = 64;
				ip_dest->protocol = IPPROTO_ICMP;
				ip_dest->check = checksum((uint16_t *)ip_dest, sizeof(struct iphdr));
				
				// eth hdr
				eth_dest->ether_type = htons(0x0800);
				memcpy(eth_dest->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
				get_interface_mac(interface, eth_dest->ether_shost);
				send_to_link(interface, dest, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct  icmphdr));
			
				continue;
			}

			//sursa mac = dest mac
			get_interface_mac(next.interface, eth_hdr->ether_shost);
			uint16_t ip_hdr_checksum = checksum((uint16_t*)ip_hdr, sizeof(struct iphdr));
			ip_hdr->check = htons(ip_hdr_checksum);
			
			// caut adresa destinatie mac
			struct arp_entry mac = search_mac_by_ip(arp_table, next.next_hop);
		
			// eth dhost = broadcast mac addr
			memmove(eth_hdr->ether_dhost, mac.mac, sizeof(uint8_t) * 6);
			// eth_hdr->ether_dhost = mac.mac;

			send_to_link(next.interface, buf, len);
		} else if (ethernet_type == 0x0806) {
			// printf("arp\n");
			// atat am putut face =)))
		}
	}
}



