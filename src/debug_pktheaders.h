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

void print_128_bits(void* data);

void print_bytes_n(void* data, u_int n);

void print_binary_char( u_char* data);

void print_binary( u_char* data, int len);


//void* print_ip_list(ip_list list);

#endif


