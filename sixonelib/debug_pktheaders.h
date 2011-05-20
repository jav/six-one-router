/** @file sixonelib/debug_pktheaders.h
 *  @brief Debug functions for packet headers
 *  @author Javier Ubillos
 *  @date 2008-07-11
 */

#ifndef DEBUG_PKTHEADERS_H
#define DEBUG_PKTHEADERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

#include <sys/types.h>
#include <sys/socket.h> // required by ip6.h
#include <netinet/in.h> // required by ip6.h
#include <netinet/ip6.h>

#include <net/ethernet.h>


/**
 * @brief Print(f) debug information about the ethernet packet
 * @param packet a pointer to the binary data
 */

void* print_eth_header(const u_char *packet);

/**
 * @brief Print(f) debug information about the ip packet
 * @param packet a pointer to the binary data
 */


void* print_ip_header(u_char *packet);

/**
 * @brief Print(f) debug information about the icmp packet
 * @param packet a pointer to the payload data
 */
void* print_icmp_header(u_char *packet);

/**
 *  @brief Print a binary 128bits long structure (in binary)
 *  @param data Pointer to the memory to print
 */

void* print_128_bits(void* data);

void* print_bytes_n(void* data, u_int n);

void print_binary_char( u_char* data);

void print_binary( u_char* data, int len);


//void* print_ip_list(ip_list list);

#endif


