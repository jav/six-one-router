/* Copyright (c) 2008, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @file debug_pktheaders.c
 *  @brief Debug functions for packet headers
 *  @author Javier Ubillos
 *  @date 2008-07-11
 */

#include "debug_pktheaders.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

#include <ifaddrs.h>

#include <net/ethernet.h>
#include <sys/types.h>
#include <sys/socket.h> // required by ip6.h
#include <netinet/in.h> // required by ip6.h
#include <netinet/ip6.h>
#include <netinet/icmp6.h>




void* print_eth_header(const u_char *packet)
{
	int i;
	struct ether_header *ethhdr;
	ethhdr = (void*) packet;
	char** ipv;
	int ipc;

	char* ether_add = ethhdr->ether_shost;

	printf("Ethernet  p: %8p +-+- size: %8d +-+-+-+-+-+-+-+-+-+-+\n", packet, sizeof(struct ether_header));
	printf("|                                             ");
	for( i=0; i < ETHER_ADDR_LEN ; i++) {
		printf("%.2X", ethhdr->ether_shost[i]);
		if(i < ETHER_ADDR_LEN -1) printf(":");
	}
	printf(" |\n");
	printf("|                                             ");
	for( i=0; i < ETHER_ADDR_LEN ; i++) {
		printf("%.2X", ethhdr->ether_dhost[i]);
		if(i < ETHER_ADDR_LEN -1) printf(":");
	}

	printf(" |\n");  
	printf("|                      %#04x |\n", ethhdr->ether_type);
	
	fflush(stdout);
	
	return (void*) ( packet + sizeof(struct ether_header) ) ; 
}

void* print_ip_header(u_char *packet) 
{
	int i;
	struct ip6_hdr *ip = (struct ip6_hdr*) packet;
	u_char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	u_char ip_type[15];

	memset(src, 0, INET6_ADDRSTRLEN);
	memset(dst, 0, INET6_ADDRSTRLEN);

	inet_ntop(AF_INET6, &ip->ip6_src, src, sizeof(src));
	inet_ntop(AF_INET6, &ip->ip6_dst, dst, sizeof(dst));

	switch(ip->ip6_nxt) {
	case IPPROTO_IPV6:
		sprintf(ip_type, "IPPROTO_IPV6"); break;
	case IPPROTO_ICMPV6:
		sprintf(ip_type, "IPPROTO_ICMPV6"); break;
	case ND_NEIGHBOR_SOLICIT:
		sprintf(ip_type, "NEIGH_SOL"); break;
	case ND_NEIGHBOR_ADVERT:
		sprintf(ip_type, "NEIGH_ADV"); break;
	case ND_REDIRECT:
		sprintf(ip_type, "ND_REDIRE"); break;
	case IPPROTO_TCP:
		sprintf(ip_type, "IPPROTO_TCP"); break;
	case IPPROTO_UDP:
		sprintf(ip_type, "IPPROTO_UDP"); break;
	default:
		sprintf(ip_type, "%15d", ip->ip6_nxt);
	}

	printf("IP -+-+-+- p:%8p +-+- size: %8d +-+-+-+-+-+-+-+-+-+-+\n", packet, ip->ip6_plen);
	printf("| %7d |    %10d | flowlabel:                 %08X |\n", ip->ip6_vfc, -1,  ip->ip6_flow);
	printf("| len:         %16d | %15s |    % 8hd |\n", ip->ip6_plen, ip_type, ip->ip6_hlim);
	printf("| src:            %41s     |\n", src);
	printf("| dst:            %41s     |\n", dst);
	if(0 >= strlen(src)); printf("src: "); print_128_bits(&ip->ip6_src);printf("\n");
	if(0 >= strlen(dst)); printf("dst: "); print_128_bits(&ip->ip6_dst);printf("\n");

	return (void*) ( packet + sizeof(struct ip6_hdr) );
}

void* print_icmp_header(u_char *packet)
{
	int i;
	struct icmp6_hdr *icmp = (struct icmp6_hdr*) packet;
	u_char* payload = ((u_char*) icmp + sizeof(*icmp));
	u_char icmp_type[10];
  
	switch(icmp->icmp6_type) {
	case ICMP6_ECHO_REQUEST:
		sprintf(icmp_type, "ECHO_REQU"); break;
	case ICMP6_ECHO_REPLY:
		sprintf(icmp_type, "ECHO_REPL"); break;
	case ND_NEIGHBOR_SOLICIT:
		sprintf(icmp_type, "NEIGH_SOL"); break;
	case ND_NEIGHBOR_ADVERT:
		sprintf(icmp_type, "NEIGH_ADV"); break;
	case ND_REDIRECT:
		sprintf(icmp_type, "ND_REDIRE"); break;
	default:
		sprintf(icmp_type, "%9d", icmp->icmp6_type);
	}

	printf("ICMP -+-+- p:%8p +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n", packet);
	printf("| %s | %8d  |                     %16X  |\n", icmp_type, icmp->icmp6_code, icmp->icmp6_cksum);

	switch(icmp->icmp6_type) {
	case ICMP6_ECHO_REQUEST:
		printf("| Id: %25hd | Seq: %24hd |\n", *(payload), *(payload + 2));
		break;
	case ICMP6_ECHO_REPLY:
		printf("| Id: %25hd | Seq: %24hd |\n", *(payload), *(payload + 2));
		break;
  }

	printf("\n");
	return (void*) ( packet + sizeof(struct icmp6_hdr) );
}

void print_128_bits(void* data)
{
	int i;
	for (i = 0; i < 15; i++)
		printf("%.2X:", ((u_char*)data)[i]);

	printf("%.2X\n", ((u_char*)data)[i]);
	return;
}

void print_bytes_n(void* data, u_int n)
{
	int i,j;
	int rowlen = 8;
	int rows = n / rowlen +1;
	
	for (i = 0; i < rows; i++){
		for(j = 0; j < rowlen; j++ ){
			printf( "%.2X", (((u_char*)(data))[j+i*rowlen])  );
			j < (rowlen-1) ? printf(":"):printf("\n");
		}
	}
	return;
}

void print_binary_char( u_char* data)
{
	printf( 0x80 & *data ? "1":"0");
	printf( 0x40 & *data ? "1":"0");
	printf( 0x20 & *data ? "1":"0");
	printf( 0x10 & *data ? "1":"0");
	printf(" ");
	printf( 0x8 & *data ? "1":"0");
	printf( 0x4 & *data ? "1":"0");
	printf( 0x2 & *data ? "1":"0");
	printf( 0x1 & *data ? "1":"0");
	return;
}
void print_binary( u_char* data, int len)
{
	int i = 0;
	for( i = 0; i < len; i++) {
		print_binary_char(&data[i]);
		printf(" ");
	}
	printf("\n");
}


