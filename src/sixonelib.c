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



/** @file sixonelib.c
 *  @brief Six-One Router library
 *  @author Javier Ubillos
 *  @date 2008-08-06
 */

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <stdio.h>

#include "sixonelib.h"
#include "sixonetypes.h"

#include <pcap.h>

#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <net/if_tun.h>
#include <sys/param.h>
#include <net/ethernet.h>

#include <sys/socket.h>  // required by ip6.h
#include <netinet/in.h>  // required by ip6.h
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <pthread.h>

#include <stdarg.h>

/// @brief DBG enable/disable debug output (should be an #ifdef really)
#define DBG 1
#ifdef DBG
#include "debug_pktheaders.h"
/// @brief DBG_P macro for debug printouts
#define DBG_P( ... ) (printf("%s :: %d :: %s():: " , __FILE__, __LINE__, __FUNCTION__), printf(__VA_ARGS__) )
//#define DBG_P // 
#endif


// Ethernet headers are allways 14 bytes long
#define SIZE_ETHERNET_HDR 14
#define SIXONE_MTU 12000
#define ICMPV6_HDR_LEN 4

/// @brief set IP version (currently only supporting 6)
#define IP 6

char sixone_errbuf[PCAP_ERRBUF_SIZE];
pcap_t **sixone_pcap_handles;
u_int sixone_pcap_handles_count;
pthread_t *sixone_threads;
u_int sixone_threads_count;
u_int sixone_packet_count;
sixone_settings global_sixone_settings;

u_int start_sixone(sixone_settings settings)
{
	int i, j,rc;
	u_char* dev;
	pthread_attr_t attr;
	// pointer pair to global_settings and interface
	u_char** set_n_if;
	u_char ip_str[INET6_ADDRSTRLEN];
	struct in6_addr default_route;

	DBG_P(" : START start_sixone()\n" );

	global_settings = settings;
	print_settings(global_settings);
	sixone_packet_count = 0;

	global_settings->out_fd = sixone_start_out_if();
	atexit(&sixone_stop_out_if);

	// you shouldn't run start_sixone twice, if you do, there'll be memory leaks!
	sixone_threads_count = global_settings->if_c; 
	sixone_threads = malloc( sixone_threads_count * sizeof(pthread_t));
	if(NULL == sixone_threads) {
		printf("could not malloc(%d) (sixone_pthreads)\n", sixone_threads_count * sizeof(pthread_t));
		exit(1);
	}
  
	memset(&default_route, 0, sizeof(default_route));
  
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	for( i=0; i < global_settings->if_c; i++) {
		printf("Starting %s\n", global_settings->if_v[i]->if_name);

		set_n_if = (u_char**) malloc(sizeof(sixone_settings) + sizeof(sixone_if));
		set_n_if[0] = (u_char*)global_settings;
		set_n_if[1] = (u_char*)global_settings->if_v[i];

		rc = pthread_create(&sixone_threads[i], &attr, start_interface, set_n_if);
		if(rc != 0)
			printf("pthread %d failed with error code %d\n", i, rc);
		else
			printf("pthread %d should be started\n", i);

	}

	for( i=0; i < global_settings->if_c; i++) {
		DBG_P(" : start_sixone() : (main thread waiting for children) pthread_join(%s)\n", global_settings->if_v[i]->if_name);
		pthread_join(sixone_threads[i], NULL);
	}

	return 0;
}

int sixone_start_out_if()
{
	struct stat buf;
	char cmd[100];
	int fd;
	int tunhead = 1, tundbg = 1;
	char tunif[SPECNAMELEN +1] ;

	DBG_P(" : sixone_start_out_if()\n");
 
	fd = open("/dev/tun", O_RDWR);
	if (fd < 0)
		err(1, "Can't open %s\n", "/dev/tun");

	if(ioctl(fd, TUNSDEBUG, &tundbg) < 0)
		err(1, "ioctl - TUNSDEBUG");

	if(ioctl(fd, TUNSIFHEAD, &tunhead) < 0)
		err(1, "ioctl - TUNSIFHEAD");
	
	if (fstat(fd, &buf) < 0)
		err(1, "stat");

	devname_r(buf.st_rdev, buf.st_mode & S_IFMT, tunif, sizeof(tunif));
  
	// This should be possible to do with netlink sockets, but this required less reading.
	snprintf(cmd, sizeof(cmd), "ifconfig %s inet6 10::1 10::2 prefixlen 128 up", tunif);
	system(cmd);
	DBG_P(" : sixone_start_out_if() : %s opened fd:%d \n",cmd, fd);
	return fd;
}

void sixone_stop_out_if() 
{
	/// @todo Stop and kill interface
	//  char cmd[100];
	//  snprintf(cmd, sizeof(cmd), "ifconfig %s destroy", tunif);
	//  system(cmd);
}

void start_interface(void* args)
{
	pcap_t *handle;
	u_char** set_n_if = ((u_char**) args);
  
	sixone_if _dev = (sixone_if)set_n_if[1];

	DBG_P("threadid:%d\n",_dev->if_name, (int)pthread_self());
	DBG_P("starting: %s\n", _dev->if_name );
  
	// setup the device
	handle = pcap_open_live(_dev->if_name, BUFSIZ, 0, 1000, sixone_errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", _dev->if_name, sixone_errbuf);
		return;
	}

	// Apply the filter(s)
	DBG_P("passing to set_filter(%s)\n", _dev->if_name);
	set_filter(handle, _dev);
  
	// start blocking sixone_loop
	DBG_P("[][][] Listening for packets threadid: %d [][][]\n", (int)pthread_self());
	pcap_loop(handle, 0, got_packet, args);
  
	DBG_P("(%s)\n",_dev->if_name);
	pthread_exit(NULL);
}


/// @TODO: Fix destroy mutexes
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;
	u_char *pkt = (u_char*) packet;
	struct ether_header *eth_hdr = (struct ether_header *) packet;
	struct ip6_hdr *ip = (struct ip6_hdr *) (eth_hdr + 1); // +1 ethernet header length
	struct icmp6_hdr *icmp = (struct icmp6_hdr *) (ip + 1); // +1 ip header length
	u_char** set_n_if = (u_char**) args;
	u_int quit = 0;
	sixone_if _dev = (sixone_if)set_n_if[1];

	struct in6_addr dbg1;
	struct in6_addr dbg2;
	int h;
  
	u_char src_ip[INET6_ADDRSTRLEN];
	u_char dst_ip[INET6_ADDRSTRLEN];

	DBG_P("MUTEX LOCK\n");
	pthread_mutex_lock( &_mutex );

	DBG_P("%s:%d : [%s] Caught a packet! [%d]\n",_dev->if_name, ++sixone_packet_count);
	++sixone_packet_count;

	DBG_P("IP->LEN = %d\n", ip->ip6_plen );
	if( ip->ip6_plen > SIXONE_MTU) {
		packet_too_big(ip);
		pthread_mutex_unlock( &_mutex);
		DBG_P("MUTEX UNLOCK - ICMP packet too big!\n");
		return;
	}

	switch(icmp->icmp6_type) {
	case ND_ROUTER_SOLICIT:
	case ND_ROUTER_ADVERT:
	case ND_NEIGHBOR_SOLICIT:
	case ND_NEIGHBOR_ADVERT:
	case ND_REDIRECT:
	case ICMP6_DST_UNREACH:
		//case ICMP6_PACKET_TOO_BIG:
	case ICMP6_TIME_EXCEEDED:
	case ICMP6_PARAM_PROB:
		pthread_mutex_unlock( &_mutex);
		DBG_P("MUTEX UNLOCK - ignored ICMPtype\n");
		//pthread_mutex_destroy(&_mutex);
		//DBG_P("MUTEX DESTROY\n");
		return;
	}
      
	print_eth_header((void*)eth_hdr);
	DBG_P(" incoming packet:\n");
	print_ip_header((void*)ip);
	//  print_icmp_header((void*)icmp);
   
	printf("[%d] \n", sixone_packet_count);

	if(is_inbound(ip)) {
		DBG_P("inbound!\n");
		inbound(ip);
	}
	else if(is_outbound(ip)) {
		DBG_P("outbound!\n");
		outbound(ip);
	}
	else {
		/// if !is_inbound && !is_outbound ignore packet
		/// however, it could be a packet directed _for_ the router
		/// @todo handle packets directed for the router

		inet_ntop(AF_INET6, &ip->ip6_src, src_ip,  sizeof(src_ip));
		inet_ntop(AF_INET6, &ip->ip6_dst, dst_ip,  sizeof(dst_ip));
		DBG_P("Ignoring packet: %s -> %s\n", src_ip, dst_ip );
	}

	pthread_mutex_unlock( &_mutex);
	DBG_P("MUTEX UNLOCK\n");
  
	//pthread_mutex_destroy(&_mutex);
	//DBG_P("MUTEX DESTROY");
	return;
}

/// @TODO Abstract, encapsulate and beautify the parsing and filter-generation, this hould be a 10 lines function, not 100 lines.
int set_filter(pcap_t *handle, sixone_if dev)
{
	int i,j,k,l;
	int _strlen = 0;
	char *bpf_exp, *bpf_exp_buff;
	char str_net[INET6_ADDRSTRLEN], str_ip[INET6_ADDRSTRLEN];
	struct in6_addr *tmp_net;
	struct in6_addr *tmp_ip;
  
	struct bpf_program bpf_p;
  
	DBG_P(" : (start)set_filter(, %s)\n", dev->if_name);
  
	// All edge interfaces should 'hear' packets from the edge not to to the edge
	// All transit interfaces should hear packets to the edge, not from the edge
  
	DBG_P("making filter\n");
	for( i=0; i < global_settings->if_c; ++i) {
		for( j=0; j < global_settings->if_v[i]->net_c; ++j) {
			if( global_settings->if_v[i]->net_v[j]->edge) {
				// dst net edge and src not edge
				// OR
				// src net edge and dst not edge
				_strlen += strlen("( ");
				_strlen += ( strlen("( ip6 dst net ") + INET6_ADDRSTRLEN + strlen(" and ") +
					     strlen("not ip6 src net ") + INET6_ADDRSTRLEN + strlen(" ) ")+
					     strlen(" or ") +
					     strlen("( ip6 src net ") + INET6_ADDRSTRLEN + strlen(" and ") +
					     strlen(" not ip6 dst net ") + INET6_ADDRSTRLEN + strlen(" ) ")
					);

				for(k=0;k < global_settings->if_c; ++k) {
					_strlen += strlen(" and not ip6 src ") + INET6_ADDRSTRLEN;

				}
				_strlen += strlen( " )");
			}
			_strlen += (j-1) * strlen(" or ");
		}
	}

	bpf_exp = (char*) malloc( _strlen +1 );// +1 null char
	memset(bpf_exp,0, _strlen+1);
  
	for( i=0; i < global_settings->if_c; ++i) {
		if(i > 0) {
			strcat(bpf_exp, " or ");      
		}

		for( j=0; j < global_settings->if_v[i]->net_c; ++j) {
			if(j > 0) {
				strcat(bpf_exp, " or ");      
			}

			tmp_net = extractPrefix(global_settings->if_v[i]->net_v[j]->addr);
			inet_ntop( AF_INET6, tmp_net, str_net, INET6_ADDRSTRLEN );
      
			sprintf( bpf_exp + strlen(bpf_exp), "( ");
			sprintf( bpf_exp + strlen(bpf_exp), "( ip6 dst net %s/%u and not ip6 src net %s/%u )", 
				 str_net, global_settings->if_v[i]->net_v[j]->addr->pfx,
				 str_net, global_settings->if_v[i]->net_v[j]->addr->pfx );
			sprintf( bpf_exp + strlen(bpf_exp), " or ");
			sprintf( bpf_exp + strlen(bpf_exp), "( ip6 src net %s/%u and not ip6 dst net %s/%u )", 
				 str_net, global_settings->if_v[i]->net_v[j]->addr->pfx,
				 str_net, global_settings->if_v[i]->net_v[j]->addr->pfx );

			for(k=0; k < global_settings->if_c; ++k) {
				for(l=0; l < global_settings->if_v[k]->net_c; ++l) {
					inet_ntop( AF_INET6, global_settings->if_v[k]->net_v[l]->addr, str_ip, INET6_ADDRSTRLEN );
					sprintf(bpf_exp + strlen(bpf_exp), " and not ip6 src %s", str_ip );
				}
			}

			sprintf( bpf_exp + strlen(bpf_exp), " )");
      
		}
    
	}
  
	DBG_P("Applying filter\n\t\"%s\" to interface %s\n", bpf_exp, dev->if_name);
  
	if (pcap_compile(handle, &bpf_p, bpf_exp, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", bpf_exp, pcap_geterr(handle));
		return(2);
	}
  
	DBG_P("pcap_setfilter()\n");
	if (pcap_setfilter(handle, &bpf_p) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", bpf_exp, pcap_geterr(handle));
		return(2);
	}
	return 0;
}

struct in6_addr *extractPrefix(sixone_ip addr)
{
	struct in6_addr *_ip6addr;
	u_char* _in6_ptr, *_in6_ptr_end;
	u_int mask;
	u_int pfx = addr->pfx;
	u_char str_ip[INET6_ADDRSTRLEN];

	// prepare new buffer and pointers to start/end
	_ip6addr = malloc(sizeof(struct in6_addr));
	_in6_ptr = (u_char*)_ip6addr;
	_in6_ptr_end = _in6_ptr+sizeof(struct in6_addr);
  
	inet_ntop(AF_INET6, &addr->ip, str_ip,  sizeof(str_ip));
	DBG_P(" : extractPrefix( (%s){,%u} )\n", str_ip ,pfx);

  
	// copy the address to the new buffer (first zero it)
	memset( _in6_ptr, 0, sizeof(struct in6_addr));
	memcpy( _in6_ptr, &addr->ip, pfx/8);

	inet_ntop(AF_INET6, _in6_ptr, str_ip,  sizeof(str_ip));
  
	// if the prefix is not divisible by 8, prepare a bitmask
	if( 0 != pfx % 8) {
		//DBG_P(" : extractPrefix() : Masking mem, byte: %d shifting: %d)\n", __FILE__, __LINE__, pfx/8 +1, 8-pfx%8);
		mask = 0xFF;
		mask <<= (8 - pfx%8); // the mask to mask out the pointed to byte
		*( ((u_char*)_in6_ptr) + pfx/8+1) &=  mask;
	}

	inet_ntop(AF_INET6, _in6_ptr, str_ip,  sizeof(str_ip));
	DBG_P(" : extractPrefix() : returns %s \n", __FILE__, __LINE__,str_ip);

	return _ip6addr;
}

void inbound(struct ip6_hdr *ip)
{
	int i= 0, j = 0;
	u_char dbg_ip[INET6_ADDRSTRLEN];
	ip_list list;
	sixone_ip ip_dst;
	sixone_ip ip_src;
	u_char str_ip_src[1024];
	u_char str_ip_dst[1024];
	struct in6_addr ipBuffer;
	u_char cmd[2048];
	sixone_ip old, new;
	u_int16_t cksumA, cksumB;
  
	old = alloc_sixone_ip();
	new = alloc_sixone_ip();
	memset(str_ip_src, 0, strlen(str_ip_src));
  
	DBG_P(" <------ \n");

	// resolve to source edge
	if( bilateral_bit(ip) ) {

		// If you wish to add the remote net to some 'is-upgraded' database
		// this addition should be here.

		list = retrieve_mappings(((sixone_ip){&ip->ip6_src, 128}), 0);
		ip_src = policy_pick_src(list);
		DBG_P("ip_src:%p\n",ip_src);

		inet_ntop(AF_INET6, &ip_src->ip, str_ip_src,  sizeof(str_ip_src));

		DBG_P("resolved mapping to: %s/%d\n", str_ip_src, ip_src->pfx);
    
		// rewrite source
		write_prefix(&ip->ip6_src, ip_src);

		// rewrite destination
		for(i = 0; i < global_settings->if_c; i++) {
			for(j = 0; j < global_settings->if_v[i]->net_c; j++) {
				if(global_settings->if_v[i]->net_v[j]->edge) {
					ip_dst = global_settings->if_v[i]->net_v[j]->addr;
				}
			}
		}
		write_prefix(&ip->ip6_dst, ip_dst);
    
		// forward 
		forward_packet(ip);
	}
	else {// NO, source was legacy
		// setup a nat rule
		// packet must have passed through, so just ignore
		DBG_P(" - rewrite destination() (nxt:%hd)\n", ip->ip6_nxt);

		cksumA = get_icmp6_checksum(ip);
		//DBG_P("cksumA = get_icmp6_checksum(ip) : %hX\n", cksumA);
		//print_binary(&cksumA, 2); printf("\n");
		memcpy( &old->ip , &ip->ip6_dst, sizeof(struct in6_addr));

		// rewrite destination
		for(i = 0; i < global_settings->if_c; i++) {
			for(j = 0; j < global_settings->if_v[i]->net_c; j++) {
				if(global_settings->if_v[i]->net_v[j]->edge)
					new = global_settings->if_v[i]->net_v[j]->addr;
			}
		}
		new->pfx = 64;
		assert(new != 0);

		print_ip_header((u_char *)ip);
		write_prefix(&ip->ip6_dst, new);
    
		print_ip_header((u_char *)ip);

		cksumB = get_icmp6_checksum(ip);

		assert( 0xFFFF == cksumB );

		forward_packet(ip);
	}
	return;
}

void outbound(struct ip6_hdr *ip)
{
	int i= 0, j = 0;
	u_char dbg_ip[INET6_ADDRSTRLEN];
	ip_list list;
	sixone_ip ip_dst;
	sixone_ip ip_src;
	u_char str_ip_dst[1024];
	struct in6_addr ipBuffer;
	u_char cmd[2048];
	sixone_ip old, new;
	u_int16_t cksumA, cksumB;
  
	memset(str_ip_dst, 0, strlen(str_ip_dst));
  
	DBG_P(" ------> \n");

	// first check if the target is upgraded or not
	// YES, target is upgraded
	if( is_sixone((sixone_ip){&ip->ip6_dst , 128}) ) {
		// resolve to transit dest
		list = retrieve_mappings((sixone_ip)((sixone_ip){&ip->ip6_dst, 128}), 0);
		ip_dst = policy_pick_dst(list);

		/// @todo More intelligent interface selection and/or policy based.
		// add route to transit dst
		// find an outgoing net  just take ANY
		DBG_P( "Looking for an exit path...\n"  );
		for(i = 0; i < global_settings->if_c; i++) {
			for(j = 0; j < global_settings->if_v[i]->net_c; j++) {
				if(!global_settings->if_v[i]->net_v[j]->edge) {
					add_route( &ip_dst->ip, ip_dst->pfx, 
						   global_settings->if_v[i]->net_v[j]->gw);
					break;
				}
			}
		}
    
		inet_ntop(AF_INET6, &ip_dst->ip, str_ip_dst,  sizeof(str_ip_dst));
		DBG_P("outbound() : resolved mapping to: %s/%d\n", str_ip_dst, ip_dst->pfx);
    

		// rewrite destination
		write_prefix(&ip->ip6_dst, ip_dst);

		// rewrite source
		for(i = 0; i < global_settings->if_c; i++) {
			for(j = 0; j < global_settings->if_v[i]->net_c; j++) {
				if(!global_settings->if_v[i]->net_v[j]->edge)
					ip_src = global_settings->if_v[i]->net_v[j]->addr;
			}
		}
		write_prefix(&ip->ip6_src, ip_src);

		// Set bilateral bit
		set_bilateral_bit(ip, 1);
		DBG_P("diagnostic: bilateralbit %d\n", bilateral_bit(ip) );

		// forward 
		forward_packet(ip);

 
	} else { // NO, target is legacy
		// setup a nat rule
		// packet must have passed through, so just ignore
		DBG_P("rewrite source() Legacy target (nxt:%hd)\n", ip->ip6_nxt);
		cksumA = get_icmp6_checksum(ip);
		DBG_P("cksumA = get_icmp6_checksum(ip) : %hX\n", cksumA);

		old = alloc_sixone_ip();

		memcpy( &old->ip , &ip->ip6_src, 16);
    
		// rewrite source to transit address
		ip_src = 0;
		for(i = 0; i < global_settings->if_c; i++) {
			for(j = 0; j < global_settings->if_v[i]->net_c; j++) {
				if(!global_settings->if_v[i]->net_v[j]->edge){
					new = global_settings->if_v[i]->net_v[j]->addr;
				}
			}
		}

		assert(new != 0);

		write_prefix(&ip->ip6_src, (sixone_ip)&new->ip); //printf("\n");

		cksumNeutralIp( &ip->ip6_src, &old->ip);
    
		cksumB = get_icmp6_checksum(ip);
		DBG_P("cksumB = get_icmp6_checksum(ip) : %hX\n", cksumB);
		//print_binary(&cksumB, 2); printf("\n");
    
		assert( 0xFFFF == cksumB );

		// add route to transit dst
		// find an outgoing net  just take ANY
		DBG_P( "Looking for an exit path...\n"  );
		for(i = 0; i < global_settings->if_c; i++) {
			for(j = 0; j < global_settings->if_v[i]->net_c; j++) {
				if(!global_settings->if_v[i]->net_v[j]->edge) {
					add_route( &ip->ip6_dst, 128, 
						   global_settings->if_v[i]->net_v[j]->gw);
					break;
				}
			}
		}
		forward_packet(ip);
	}
	return;
}

void forward_packet(struct ip6_hdr *ip)
{
	/// @todo Persistent socket!
  
	int fd = 0, nbytes, maxbytes = 0;
	uint32_t family;
	struct iovec ip_vec[2];
	//  DBG_P(" : forward_packet( ) : using fd:%d\n", __FILE__, __LINE__, global_settings->out_fd);

	if((sizeof(*ip) + ip->ip6_plen) > 15000) {
		DBG_P("IGNORING PACKET!!! (%d)\n", sizeof(*ip) + ip->ip6_plen);
		/// @todo Send an ICMP - Fragmentation Needed packet.
		return;
	}

	fd = global_settings->out_fd;
	if(0 == fd)
		err(1,"no fd");

	family = htonl((uint32_t)AF_INET6);

	ip_vec[0].iov_base = &family;
	ip_vec[0].iov_len = sizeof(family);
	ip_vec[1].iov_base = ip;
	ip_vec[1].iov_len = sizeof(*ip) + ip->ip6_plen;

	nbytes = writev(fd, ip_vec, 2);
        DBG_P(" : forward_packet( ) : wrote %d bytes.\n", __FILE__, __LINE__, nbytes);
	DBG_P(" : forward_packet( ) : family:%hd, *ip:%d, ip6_len:%d .\n", AF_INET6, sizeof(*ip) , ip->ip6_plen );
  
	//print_ip_header(ip);
	//print_icmp_header( (struct icmp6_hdr *) (ip + 1) );

	print_ip_header((u_char *)ip);

	if( sizeof(*ip) + ip->ip6_plen > maxbytes) maxbytes = sizeof(*ip) + ip->ip6_plen;
	DBG_P("Want to write %d bytes, max so far is %d\n", sizeof(*ip) + ip->ip6_plen, maxbytes);

	if( nbytes != sizeof(family) + sizeof(*ip) + ip->ip6_plen) {
		DBG_P(" too few written bytes %d should have written %d| error:%s (errorcode: %d)\n", nbytes, sizeof(family) + sizeof(*ip) + ip->ip6_plen,strerror(errno), errno);
		perror("ioerror");
		exit(1);
	}
	else {
		DBG_P(" : Sent packet. nbytes = %d \n", nbytes);
	}

	return;
}

int cmp_bits(void* left, void* right, u_int bits)
{
	u_int _bytes_to_malloc;
	void* _left;
	void* _right;
	u_char _mask;

	_bytes_to_malloc = bits/8;


	_left = (void*) malloc(_bytes_to_malloc);
	_right = (void*) malloc(_bytes_to_malloc);

	if( 0 != bits%8)
	{
		_bytes_to_malloc += 1; // if we got a tail of bits, include them
		_mask = 0xFF << 8 - bits % 8; // prepare a mask for the last bits (8)
	}

	memcpy(_left, left, _bytes_to_malloc); // Copy the two bitstrings
	memcpy(_right, right, _bytes_to_malloc);

	if( 0 != bits%8) // if we
	{
		((u_char*)_left)[_bytes_to_malloc] &= _mask; // zero out any unessecary bit tail
		((u_char*)_right)[_bytes_to_malloc] &= _mask;      
	}

	return memcmp(_left, _right, _bytes_to_malloc);
  
}

void extract_postfix(u_char* buffer, u_int offset, u_int totLen)
{
	u_char _mask;
	u_int _bitShift;

	DBG_P(" (%p, %d)\n", buffer, offset);
	memset(buffer, 0, offset/8); // zeroout the first bytes

	_bitShift = offset % 8;
	_mask = 0xFF >> _bitShift;
	buffer[offset/8] &= _mask;

	return;
}

void extract_prefix(u_char* buffer, u_int offset, u_int totLen)
{
	u_char _mask;
	u_int _bitShift;
	u_int _tailLength;
	int i;
	DBG_P(" (%p, %d, %d)\n", buffer, offset, totLen);
	if( 0 == offset % 8 ) {
		memset(&buffer[offset/8], 0, totLen/8 - (offset/8));
	}
	else {
		memset(&buffer[offset/8+1], 0, totLen/8 - (offset/8-1));
		_bitShift = 8 - offset % 8;
		_mask = 0xFF << _bitShift;
		buffer[offset/8] &= _mask;
	}
  
	return;
}

void or_arrays(u_char* buff1, u_char* buff2, u_int len)
{
	u_int i;
	for(i=0; i < len; i++)
		buff1[i] |= buff2[i];
}


/// @todo make this a macro (inline)
u_int is_inbound(struct ip6_hdr *ip)
{
	int i,j, src=0, dst=0; // src,dst = 0 if transit, 1 if edge
	sixone_if dev;
	sixone_net net;

	// if dst is our transit net, then go for it!

	for (i = 0; i < global_settings->if_c; ++i)    {
		dev = global_settings->if_v[i];
    
		for(j = 0; j < dev->net_c; ++j){
			if(!dev->net_v[j]->edge) {
				// is dst an edgenet?
				if(0 == cmp_bits((void*) &ip->ip6_dst, &dev->net_v[j]->addr->ip, dev->net_v[j]->addr->pfx) ) {
					return 1;
				}
			}
		}
	}
	return 0;
}

/// @todo make this a macro (inline)
u_int is_outbound(struct ip6_hdr *ip)
{
	int i,j, src=0, dst=0; // src,dst = 0 if transit, 1 if edge
	sixone_if dev;
	sixone_net net;
	char str_net[INET6_ADDRSTRLEN], str_ip[INET6_ADDRSTRLEN];

	// if src is an edge net and dst is not that very same edgenet
	// we don't do horisontal routing
	// packet is outbound if src=1 and dst=0
	// redundant check, because the packet filtering checks the
	// source:destination pair
	// but let's futureproof
  
	for (i = 0; i < global_settings->if_c; ++i)    {
		dev = global_settings->if_v[i];
    
		for(j = 0; j < dev->net_c; ++j) {
			if(dev->net_v[j]->edge) {
				// is dst an edgenet?
				inet_ntop( AF_INET6, &ip->ip6_dst , str_ip, INET6_ADDRSTRLEN );
				inet_ntop( AF_INET6,  &dev->net_v[j]->addr->ip , str_net, INET6_ADDRSTRLEN );

				if(0 == cmp_bits((void*) &ip->ip6_dst, &dev->net_v[j]->addr->ip, dev->net_v[j]->addr->pfx) ) {
					dst=1;
				}
				// is src an edgenet?
				inet_ntop( AF_INET6, &ip->ip6_dst , str_ip, INET6_ADDRSTRLEN );
				inet_ntop( AF_INET6,  &dev->net_v[j]->addr->ip , str_net, INET6_ADDRSTRLEN );

				if(0 == cmp_bits((void*) &ip->ip6_src, &dev->net_v[j]->addr->ip, dev->net_v[j]->addr->pfx)) {
					src=1;
				}
			}
		}
	}

	return !(dst) && src;
}

/// @todo make smart (binary tree?)
u_int is_edge(struct in6_addr *ip)
{
	int i,j;
	for ( i = 0; i < global_settings->if_c; i++)  {
		for( j = 0; global_settings->if_v[i]->net_c; j++)  {
			if( global_settings->if_v[i]->net_v[j]->edge 
			    && 
			    0 == cmp_bits((void*)ip, &global_settings->if_v[i]->net_v[j]->addr->ip, 128) 
				)
				return 1;
		}
	}
	return 0;
}

/// @todo Proper testing, has some (intresting) bugs.
void write_prefix(struct in6_addr *addr, sixone_ip prefix)
{
	struct in6_addr ipbuffer_prefix;
	u_char dbg_post[INET6_ADDRSTRLEN], dbg_pre[INET6_ADDRSTRLEN];

	memcpy(&ipbuffer_prefix, &prefix->ip, 16);
	inet_ntop( AF_INET6, &ipbuffer_prefix, dbg_pre, INET6_ADDRSTRLEN );
	inet_ntop( AF_INET6, addr , dbg_post, INET6_ADDRSTRLEN );
	//DBG_P("(%s, ((sixone_ip){%s, %u})) \n", dbg_post, dbg_pre, prefix->pfx);

	inet_ntop( AF_INET6, &ipbuffer_prefix, dbg_pre, INET6_ADDRSTRLEN );
	//DBG_P("pre: %s\n", dbg_pre);

	extract_prefix((u_char *)&ipbuffer_prefix, prefix->pfx, 128);
	inet_ntop( AF_INET6, &ipbuffer_prefix, dbg_post, INET6_ADDRSTRLEN );
	//DBG_P("pre: %s\n", dbg_pre);
  
	extract_postfix((u_char *)addr, (u_int)prefix->pfx, 128);
	inet_ntop( AF_INET6, addr , dbg_post, INET6_ADDRSTRLEN );
	//DBG_P("post: %s\n", dbg_post);

	or_arrays((u_char *)addr, (u_char *)&ipbuffer_prefix, 16);
	inet_ntop( AF_INET6, addr , dbg_post, INET6_ADDRSTRLEN );
	//DBG_P("result: %s\n", dbg_post);
	return;
}

u_int bilateral_bit(struct ip6_hdr *ip)
{
	DBG_P("\n");
	uint32_t flow = htonl(1);
	return ip->ip6_flow & htonl(1);
}

u_int unilateral_bit(struct ip6_hdr *ip)
{
	return !bilateral_bit(ip);
}

int set_bilateral_bit(struct ip6_hdr *ip, u_char val)
{
	DBG_P("\n");
  
	if( val == 0) // Unset bit
		ip->ip6_flow &= ~htonl(1);
	else  // Set bit
		ip->ip6_flow |= htonl(1);

	return 1;
}

int set_unilateral_bit(struct ip6_hdr *ip, u_char val)
{
	return set_bilateral_bit(ip, !val);
}

int is_sixone(sixone_ip ip)
{
	ip_list transit;
	ip_list dbg_transit;
	int dbg_counter = 0;
	transit = retrieve_mappings(ip, 1);

	DBG_P("%d\n", transit != NULL);
	return NULL != transit;
}

sixone_ip policy_pick_dst(ip_list list)
{
	DBG_P("\n");
	if(global_settings->policy->sixone_policy_dst != NULL)
		return global_settings->policy->sixone_policy_dst(list);
	else
		return policy_pick_dst_default(list);
}

sixone_ip policy_pick_src(ip_list list)
{
	DBG_P("\n");
	if(global_settings->policy->sixone_policy_src != NULL)
		return global_settings->policy->sixone_policy_src(list);
	else
		return policy_pick_src_default(list);
}

sixone_ip policy_pick_dst_default(ip_list list)
{
	DBG_P("list: %p\n", list);
	if (list == NULL) return NULL;
	else return list->ip;
}

sixone_ip policy_pick_src_default(ip_list list)
{
	DBG_P("\n");
	if (list == NULL) return NULL;
	else return list->ip;
}

ip_list retrieve_mappings_default(sixone_ip ip, u_int only_sixone)
{
	FILE* _fh;
	u_int pfx_len;
	ip_list ret;
	ip_list *curr;
	struct in6_addr edge_ip;
	struct in6_addr tran_ip;
	u_char strEdge[INET6_ADDRSTRLEN];
	u_char strTran[INET6_ADDRSTRLEN];
	u_char strOrig[INET6_ADDRSTRLEN];
	u_char _string[1024];

	ret = NULL;
	curr = &ret;

	memset(strEdge, 0, INET6_ADDRSTRLEN);
	memset(strTran, 0, INET6_ADDRSTRLEN);
	memset(strOrig, 0, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(ip->ip), strOrig, sizeof(strOrig));

	DBG_P(" got %s\n", strOrig);

	if( NULL == ( _fh = fopen( "mappings.txt", "r") ) )  {
		printf("Cannot open file mappings.txt.\n");
		exit (1);
	}

	while( NULL != fgets(_string, sizeof(_string), _fh) ) {
		sscanf(_string, "%[^/ ]/%d%s\n", strEdge,&pfx_len, strTran);
		
		inet_pton(AF_INET6, strEdge, &(edge_ip));
		inet_pton(AF_INET6, strTran, &(tran_ip));
		
		if( 0 == cmp_bits(&ip->ip, &edge_ip, pfx_len)) {
			(*curr) = (ip_list)alloc_ip_list();
			(*curr)->ip = alloc_sixone_ip();
			(*curr)->ip->ip = tran_ip;
			(*curr)->ip->pfx = pfx_len;
			curr = &(*curr)->next;
		}
   
		if( 0 == cmp_bits(&ip->ip, &tran_ip, pfx_len)) {
			(*curr) = (ip_list)alloc_ip_list();
			(*curr)->ip = alloc_sixone_ip();
			(*curr)->ip->ip = edge_ip;
			(*curr)->ip->pfx = pfx_len;
			curr = &(*curr)->next;
		}
    
	}

	return ret;
}

ip_list retrieve_mappings(sixone_ip ip, u_int only_sixone)
{
	DBG_P("\n");
	u_char strOrig[INET6_ADDRSTRLEN];
	memset(strOrig, 0, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(ip->ip), strOrig, sizeof(strOrig));

	if(global_settings->resolv->sixone_resolv != NULL)
		return global_settings->resolv->sixone_resolv(ip, only_sixone);
	else
		return retrieve_mappings_default(ip, only_sixone);
}

/// @deprecated
int add_route(struct in6_addr * ip, u_int pfx, struct in6_addr* gw)
{
	//route add -inet6 abc:: -prefixlen 64 -iface tun0
 
	int i,j;
	char cmd[2048];
	char ip_str[INET6_ADDRSTRLEN];
	char gw_str[INET6_ADDRSTRLEN];
	static char **cmdList = NULL;
	static int cmdListLen = 0;
	char* cmdListElement;

	DBG_P("%d\n", cmdListLen);
  
	assert(gw != NULL);
	if(gw == NULL) {
    
		DBG_P(": GW was NULL\n");
		return 0;
	}
 
	memset(cmd, 0, sizeof(cmd));

	// Add route for ip to go through interface out_if
	// route add 192.168.0.1/32 -iface fxp0 -cloning
	inet_ntop(AF_INET6, ip, ip_str, sizeof(ip_str));
	inet_ntop(AF_INET6, gw, gw_str, sizeof(gw_str));

	sprintf(cmd, "route add -inet6  %s/%d  %s", ip_str, pfx, gw_str);	

	for(i = 0; i<cmdListLen; i++) {
		DBG_P("COMPARING %d\n", i);
		if( 0 == strcmp(cmd, cmdList[i]) ) {
			DBG_P("MATCHED ROUTE, IGNORE\n");
			return 0;
		}      
	}

	cmdList = realloc(cmdList, (cmdListLen +1)*sizeof(void*) );
	cmdListElement = (char*) malloc(strlen(cmd));
	strcpy(cmdListElement, cmd); 
	cmdList[cmdListLen] = cmdListElement;
	cmdListLen++;
	DBG_P("ADDING NEW ROUTE\n");
	return system(cmd);
  
}

/// @todo Actually remove route!
void del_route(sixone_ip ip, sixone_if dev)
{
	return;
}

/// @todo Dummy function, always returns false
u_int route_exists(sixone_ip ip)
{
	return 0;
}

/// @deprecated
u_int16_t get_icmp6_checksum(struct ip6_hdr *ip)
{
	struct icmp6_hdr *icmp = (void *)((char *)ip + sizeof(*ip));
	void* data = ((char *)icmp + ICMPV6_HDR_LEN);  
	int data_len = ntohs(ip->ip6_plen) - ICMPV6_HDR_LEN;

	DBG_P("()\n");
	u_int16_t sum = checksum(IPPROTO_ICMPV6, icmp, ICMPV6_HDR_LEN);
	sum = checksum(sum, &ip->ip6_src, sizeof(ip->ip6_src));
	sum = checksum(sum, &ip->ip6_dst, sizeof(ip->ip6_dst));
	sum = checksum(sum, &ip->ip6_plen, sizeof(ip->ip6_plen));
	sum = checksum(sum, data, data_len);

	return sum;
}

/// @deprecated
int recalc_icmp6_checksum(struct ip6_hdr *ip)
{
	struct icmp6_hdr *icmp = (void *)((char *)ip + sizeof(*ip));
	void* data = ((char *)icmp + ICMPV6_HDR_LEN);  
	int data_len = ntohs(ip->ip6_plen) - ICMPV6_HDR_LEN;

	DBG_P("\n");
	//DBG_P("checksum before: %Xh \n", icmp->icmp6_cksum);

	icmp->icmp6_cksum = 0;
	uint16_t sum = checksum(IPPROTO_ICMPV6, icmp, ICMPV6_HDR_LEN);
	sum = checksum(sum, &ip->ip6_src, sizeof(ip->ip6_src));
	sum = checksum(sum, &ip->ip6_dst, sizeof(ip->ip6_dst));
	sum = checksum(sum, &ip->ip6_plen, sizeof(ip->ip6_plen));
	sum = checksum(sum, data, data_len);
	icmp->icmp6_cksum = ~ntohs(sum);
	//DBG_P("checksum after: %Xh \n", icmp->icmp6_cksum);

	return 1;
}

/// @deprecated
int recalc_udp_checksum(struct ip6_hdr *ip) {

	struct udphdr *udp = (void *)((char *)ip + sizeof(*ip));
	void* data = ((char *)udp + sizeof(*udp));
	int data_len = ntohs(ip->ip6_plen) - sizeof(*udp);

	DBG_P("\n");
  
	udp->uh_sum = 0;
	uint16_t sum = checksum(IPPROTO_UDP, udp, sizeof(*udp));
	sum = checksum(sum, &ip->ip6_src, sizeof(ip->ip6_src));
	sum = checksum(sum, &ip->ip6_dst, sizeof(ip->ip6_dst));
	sum = checksum(sum, &ip->ip6_plen, sizeof(ip->ip6_plen));
	sum = checksum(sum, data, data_len);
	udp->uh_sum = ~ntohs(sum);
	//DBG_P("  to: %d\n", udp->uh_sum);

	return 1;
}

/// @deprecated
int recalc_tcp_checksum(struct ip6_hdr *ip) {

	struct tcphdr *tcp = (void *)((char *)ip + sizeof(*ip));
	void* data = ((char *)tcp + sizeof(*tcp));
	int data_len = ntohs(ip->ip6_plen) - sizeof(*tcp);

	DBG_P("\n");
  
	tcp->th_sum = 0;
	uint16_t sum = checksum(IPPROTO_TCP, tcp, sizeof(*tcp));
	sum = checksum(sum, &ip->ip6_src, sizeof(ip->ip6_src));
	sum = checksum(sum, &ip->ip6_dst, sizeof(ip->ip6_dst));
	sum = checksum(sum, &ip->ip6_plen, sizeof(ip->ip6_plen));
	sum = checksum(sum, data, data_len);
	tcp->th_sum = ~ntohs(sum);
	//DBG_P("  to: %d\n", tcp->th_sum);

	return 1;
}

u_int16_t
checksum(u_int16_t sum, const void *_p, u_int16_t len)
{
	u_int16_t t;
	const u_int8_t *p = _p;
	const u_int8_t *end = p + len;

	while(p < (end-1)) {
		t = (p[0] << 8) + p[1];
		sum += t;
		if (sum < t) sum++;
		p += 2;
	}
	if(p < end) {
		t = (p[0] << 8) + 0;
		sum += t;
		if (sum < t) sum++;
	}
	return sum;
}

void cksumNeutralIp( struct in6_addr *target, struct in6_addr *prev )
{
	u_int16_t *p = (u_int16_t *)target;
	u_int16_t osum, nsum, oldWord;
	u_int16_t *oaddr = (u_int16_t *)prev;
	u_int16_t *naddr = (u_int16_t *)target;

	char dbg_ipa[INET6_ADDRSTRLEN], dbg_ipb[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, target, dbg_ipa, sizeof(dbg_ipa));
	inet_ntop(AF_INET6, prev, dbg_ipb, sizeof(dbg_ipb));
	DBG_P(" Merging %s and %s\n", dbg_ipa, dbg_ipb );

	osum = incksum16(oaddr);
	nsum = osum + ~incksum16(naddr); /* osum - nsum */

	if (nsum < osum) nsum++;

	//DBG_P("osum = %hX, nsum = %hX\n", osum, nsum);
  
	oldWord = naddr[3];
 
	naddr[3] += nsum;
  
	if( naddr[3] < oldWord )
		naddr[3]++;

	//DBG_P("() : old_p[3]:%hX => p[3]:%hX \n", oldWord, naddr[3]);
}

u_int16_t getCksumDiff16(void* a, void* b) {
	u_int16_t* oaddr = b;
	u_int16_t* naddr = a;
	u_int16_t osum, nsum;
	DBG_P("\n");
	osum = incksum16(oaddr);
	nsum = osum + ~incksum16(naddr); /* osum - nsum */

	if (nsum < osum) nsum++;

	//DBG_P("nsum = %hX\n", nsum);
	return nsum;

  
}

/**
 * @brief Internet checksum in network byte order.
 */
u_int16_t incksum16(const void *_p) {

	const uint64_t *p = _p;
	uint64_t s;
	uint32_t u, v;
	uint16_t x, y;
	DBG_P("\n");
	s = p[0];
	s += p[1];
	if (s < p[1]) s++;

	v = s >> 32;
	u = s;

	u += v;
	if (u < v) u++;

	x = u >> 16;
	y = u;

	x += y;
	if (x < y) x++;

	return x;
}

/// @todo Properly respond with ICMP-packet too big. This is only a stub (not properly working/tested)
void packet_too_big(struct ip6_hdr *ip) {

	struct icmp6_hdr *icmp = (void *)((char *)ip + sizeof(*ip));
	struct in6_addr tmp;
	DBG_P("\n");
	memset(icmp, 0, ICMPV6_HDR_LEN);
  
	// Flip source/Dest
	memcpy( &tmp, &ip->ip6_dst, sizeof(tmp));
	memcpy( &ip->ip6_dst, &ip->ip6_src, sizeof(ip->ip6_dst) );
	memcpy( &ip->ip6_src, &tmp, sizeof(ip->ip6_src) );

	// build ICMP contents
	icmp->icmp6_type = ICMP6_PACKET_TOO_BIG;
	*icmp->icmp6_data32 = htonl(SIXONE_MTU);

	ip->ip6_plen = SIXONE_MTU - sizeof(struct ip6_hdr);

	// reply to the sender
	forward_packet(ip); 
}
