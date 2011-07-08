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

/** @file sixonelib.h
 *  @brief Six-One Router library
 *  @author Javier Ubillos
 *  @date 2008-08-04
 */

#ifndef SIXONELIB_H
#define SIXONELIB_H

#include "sixonetypes.h"

#include <pcap.h>

#include <sys/socket.h> // required by ip6.h
#include <netinet/in.h> // required by ip6.h
#include <netinet/ip6.h>

sixone_settings global_settings;

/**
 *  @brief Start the sixone router with the given settings, starts a subthread for each interface.
 *  @param settings The settings to use (assumed to be loaded by load_settings()
 *  @return (not yet defined)
 *  @callergraph
 */
u_int start_sixone();

/**
 *  @brief Bring up the outgoing interface and return a filedescriptor to it
 *  @return The filedescriptor of the outgoing interface
 */
int sixone_start_out_if();

/**
 *  @brief Bring down the outgoing interface (destroy)
 *  @TODO Add code
 */
void sixone_stop_out_if();

/**
 *  @brief Receive packet
 *  @param args A pointer to a pair of sixone_settings and sixone_if (malloc(sizeof(sizone_settings) + sizeof(sixone_if))
 *  @param header pcap packet header (structure below)
 *  @code
 *      struct pcap_pkthdr {
 *          struct timeval ts;  // time stamp
 *          bpf_u_int32 caplen; // length of portion present
 *          bpf_u_int32 len;    // length this packet (off wire)
 *      };
 *  @endcode
 *  @param packet The binary data
 *  @callergraph
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/**
 *  @brief Sets the BPF for the listening pcap session (one per interface) (internal use only)
 *  @param handle The pcap handle that this filter should apply to
 *  @param dev the sixone_if that this filter applies to
 *  @param settings the sixone_settings type, to fech information about all edge nets from
 */
int set_filter(pcap_t *handle, sixone_if dev);

/**
 *  @brief Prepares and starts listening on the interface (internal use only)
 *  @param dev The sixone_if to start
 *  @callergraph
 */
void start_interface(void* args);

/**
 *  @brief Takes an address and zeroes out the "post prefix" part. That is, extracts the network part of the address
 *  @param addr The address to use as base
 *  @param pfx The amount of bits that belong to the network
 */
struct in6_addr *extractPrefix(sixone_ip addr);

/**
 * @brief Inbound program execution path
 * @param ip Packet to handle
 *  @callergraph
 */
void inbound(struct ip6_hdr *ip);

/**
 * @brief Outbound program execution path
 * @param ip Packet to handle
 *  @callergraph
 */
void outbound(struct ip6_hdr *ip);

/**
 *  @brief Send the packet (all processing is done)
 *  @param ip packet to send.
 *  @callergraph
 */ 
void forward_packet(struct ip6_hdr *ip);

/**
 *  @brief Compares two bitstrings of arbitrary bit-length, used for e.g. longest-prefix macthing
 *  @param left First bitstring to compare
 *  @param right Second bitstring to compare
 *  @param amount of bits to compare
 *  @return 0 if equal, 1 if left is 'larger', -1 if right is 'larger'
 *  @todo make this quick and and inline (macro)
 */
int cmp_bits(void* left, void* right, u_int bits);

/**
 *  @brief Takes a bitstring and zeroes out the first number of bits
 *  @param buffer A pointer to the memory
 *  @param offset Until which bit should zeroes be written? 0 = first bit is zeroed
 *  @param totLen The total bitlength of buffer (ignored!)
 *  @todo make this quick and and inline (macro)
 */
void extract_postfix(u_char* buffer, u_int offset, u_int totLen);

/**
 *  @brief Takes a bitstring and zeroes out the last number of bits
 *  @param buffer A pointer to the memory
 *  @param offset Until which bit should zeroes be written? 0 = first bit is zeroed
 *  @param totLen The total bitlength of buffer
 *  @todo make this quick and and inline (macro)
 */
void extract_prefix(u_char* buffer, u_int offset, u_int totLen);

/**
 *  @brief Takes two bitarrays and or's them together
 *  @param buff1 A pointer to the buffer to write to
 *  @param buff2 A pointer to the array to or with
 *  @param len The total byte of buffer
 *  @todo make this quick and and inline (macro)
 */
void or_bytes(u_char* buff1, u_char* buff2, u_int len);

/**
 *  @brief Checks if a packet is inbound or not.
 * 
 *  A packet is inbound if is sent to an ip within the trainsit net
 *  uni-/bi-lateral treatment is dealt with in inbound()
 *  @param ip The packet to check
 *  @return true if ip_dst is for edge or transit net and src
 *  is not from the edge net
 */
u_int is_inbound(struct ip6_hdr *ip);

/**
 *  @brief Checks if the packet is outbound or not.
 *
 *  A packet is outbound if it is recieved that is not destined 
 *  to an ip the edge net nor the transit net (
 *
 *  @todo How is external noise dealt with? that is, traffic that
 *  reaches the external interface but is not destined for the
 *  transit/edge nets?
 *  
 *  @param ip The packet to check
 *  @return true if ip_src's prefix belongs to the edge net
 *  and is not destined for the edge net
 */
u_int is_outbound(struct ip6_hdr *ip);

/**
 * @return Returns true if the ip is listed as an edgenetwork of this router
 * @param ip The ipadress we check
 * @param settings This routers configuration
 */

u_int is_edge(struct in6_addr *ip);

/** 
 *  @brief Rewrites a  packets source address to
 *  the transit address.
 *  @param addr Pointer to the IPv6 packet to rewrite
 *  @param prefix Pointer to the prefix to copy
 *  @param prefix_len Number of bits to copy from the prefix (prefix length)
 *  @param src which addess to rewrite true => src, false => dst
 */
void write_prefix(struct in6_addr *addr, sixone_ip prefix);

/**
 *  @brief Checks if the bilateral bit is set
 *  @todo Implement
 *  @param ip The ip packet.
 *  @return returns true if is bilateral
 */
u_int bilateral_bit(struct ip6_hdr *ip);

/**
 *  @brief Checks if the unilateral bit is set
 *  @todo Implement
 *  @param ip The ip packet.
 *  @return returns true if is unilateral
 */
u_int unilateral_bit(struct ip6_hdr *ip);

/**
 *  @brief Sets the bilateral bit to true/false
 *  @todo Implement
 *  @param ip The ip packet.
 *  @return returns what's set
 */
int set_bilateral_bit(struct ip6_hdr *ip, u_char val);

/**
 *  @brief Sets the uniateral bit to true/false
 *  (most likley a call to set_bilateral_bit with inverted
 *  argument).
 *  @todo Implement
 *  @param ip The ip packet.
 *  @return returns what's set
 */
int set_unilateral_bit(struct ip6_hdr *ip, u_char val);

/**
 *  @brief Checks if the destination is upgraded or not
 *  @todo Implement
 *  @param ip The ip packet.
 *  @return returns true if dest is bilateral
 */
int is_sixone(sixone_ip ip );

/**
 *  @brief If the settings->policy is set, it forwards the call
 *   else it runs the default policy
 *  @param ip_lst The list of ips
 *  @return returns the preffered dst ip
 *  @todo Implement 
 */
sixone_ip policy_pick_dst_default(ip_list list);

/**
 *  @brief If the settings->policy is set, it forwards the call
 *   else it runs the default polcy
 *  @param ip_lst The list of ips
 *  @return returns the preffered dst ip
 *  @todo Implement 
 */
sixone_ip policy_pick_dst(ip_list list);

/**
 *  @brief If the settings->policy is set, it forwards the call
 *   else it runs the default policy
 *  @param ip_lst The list of ips
 *  @return returns the preffered dst ip
 *  @todo Implement 
 */
sixone_ip policy_pick_src_default(ip_list list);

/**
 *  @brief If the settings->policy is set, it forwards the call
 *   else it runs the default policy
 *  @param list The list of ips
 *  @return returns the preffered src ip
 *  @todo Implement, and figure out behaviour
 */
sixone_ip policy_pick_src(ip_list list);

/**
 *  @brief Retrieve mappings for the destination IP, 
 *  if not specified in settings->resolv, then call the default implementation
 *  @param ip the ip to lookup
 *  @param only_sixone Only return a list if the ip is an edge IP
 *  @param settings The 'globally' defined routersettings
 *  @return the mapped destination transit address
 *  @todo manage the allocated return
 */
ip_list retrieve_mappings(sixone_ip ip, u_int only_sixone);

/**
 *  @brief Retrieve mappings for the destination IP
 *  @todo How to chose the "preffered" prefix
 *  @param ip the ip to lookup
 *  @param only_sixone Only return a list if the ip is an edge IP
 *  @param settings The 'globally' defined routersettings
 *  @return the mapped destination transit address
 *  @todo manage the allocated return
 */
ip_list retrieve_mappings_default(sixone_ip ip, u_int only_sixone);

/// @brief Adds a route
int add_route(struct in6_addr * ip, u_int pfx, struct in6_addr *gw);

/// @brief Removes a route
void del_route(sixone_ip ip, sixone_if dev);

/// Returns true if route exists
u_int route_exists(sixone_ip ip);


u_int16_t get_icmp6_checksum(struct ip6_hdr *ip);
/// @deprecated
int recalc_icmp6_checksum(struct ip6_hdr *ip);
/// @deprecated
int recalc_tcp_checksum(struct ip6_hdr *ip);
/// @deprecated
int recalc_udp_checksum(struct ip6_hdr *ip);

u_int16_t checksum(u_int16_t sum, const void *_p, u_int16_t len);

/**
 *  @brief Calculates the checksum difference when rewriting IP-addresses. Compensates for the difference by writing the difference into the 7th byte.
 *  @param target A pointer to the (IPv6) field to write to
 *  @param prev A pointer to the (IPv6) field to read from
 */
void cksumNeutralIp( struct in6_addr *target, struct in6_addr *prev );

u_int16_t getCksumDiff16(void* a, void* b);

u_int16_t incksum16(const void *_p);

void packet_too_big(struct ip6_hdr *ip);

#endif

