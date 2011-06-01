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

/** @file sixonelib/sixonetypes.h
 *  @brief Six-One Router Types
 *  @author Javier Ubillos
 *  @date 2008-08-06
 */

#ifndef SIXONETYPES_H
#define SIXONETYPES_H

#include <sys/types.h>
#include <sys/socket.h> // required by ip6.h
#include <netinet/in.h> // required by ip6.h
#include <netinet/ip6.h>

typedef struct sixone_settings_ *sixone_settings;

/// @brief Sixone ip's usually need to know the prefixlength
typedef struct sixone_ip_ *sixone_ip;
struct sixone_ip_
{
  struct in6_addr ip;
  int pfx;
};

/// @brief Sixone usualy deals with pairs of ip's.
/// OBSOLETE! 
/// @deprecated
typedef struct sixone_ip_pair_
{
  sixone_ip a;
  sixone_ip b;
} *ip_pair;

/// @brief A list of ips and their pfx_len
typedef struct ip_list_ *ip_list; // mention the type for the next pointer
struct ip_list_
{
  sixone_ip ip;
  ip_list next; /// The next ip in the list, NULL = end of list;
};

/**
 * @brief struct storing function pointers to
 * policy functions.
 */
typedef struct sixone_policy_ {
  sixone_ip (*sixone_policy_dst)(ip_list list);
  sixone_ip (*sixone_policy_src)(ip_list list);
} *sixone_policy;

/**
 * @brief struct storing function pointers to
 * resolution functions.
 */
typedef struct sixone_resolv_ {
  /**
   * @brief get the mappings for a given destination
   *  @arg ip The ip and prefix in an sixone_ip struct
   *  @arg settings The "global" settings of the router
   *  @return A list of mappings. No mappings => empty list
   */
  ip_list (*sixone_resolv)(sixone_ip ip, u_int only_sixone);

  /** 
   * @brief resolve destination
   *  @arg ip An edge ip
   *  @return a set of transit ip's  
   */
  //ip_list (*sixone_resolv_dst)(struct in6_addr ip);
  /** 
   * @brief resolve source 
   *  @arg ip An edge ip
   *  @return a set of transit ip's  
   */
  //ip_list (*sixone_resolv_src)(struct in6_addr ip);
} *sixone_resolv;

/**
 * @brief struct storing network and prefix length
 */
typedef struct sixone_net_
{
  sixone_ip addr;
  short int edge;
  struct in6_addr *gw;
} *sixone_net;

/**
 * @brief struct storing interfaces
 */
typedef struct sixone_if_
{
  u_int net_c;
  u_char* if_name;
  sixone_net *net_v;
  
} *sixone_if;

/**
 * @brief Struct keeping routers interfaces settings
 */
struct sixone_settings_
{
  u_int if_c;
  sixone_if *if_v;
  sixone_policy policy;
  sixone_resolv resolv;
  int out_fd;
};



/**
 *  @brief Allocate a sixone_ip type
 *  @return The sixone_ip type allocated (zeroed)
 */
sixone_ip alloc_sixone_ip();

/**
 *  @brief Allocate a sixone_ip_list type
 *  @return The sixone_ip_list type allocated (zeroed)
 */
ip_list alloc_sixone_ip_list();

/**
 *  @brief Allocate a sixone_policy type
 *  @return The sixone_policy type allocated (zeroed)
 */
sixone_policy alloc_sixone_policy();

/**
 *  @brief Allocate a sixone_resolv type
 *  @return The sixone_resolv type allocated (zeroed)
 */
sixone_resolv alloc_sixone_resolv();

/**
 *  @brief Allocate a sixone_settings type
 *  @return The sixone_settings type allocated (zeroed)
 */
sixone_settings alloc_sixone_settings();

/**
 *  @brief Allocate a sixone_net type
 *  @return The sixone_net type allocated (zeroed)
 */
sixone_net alloc_sixone_net();

/**
 *  @brief Allocate a sixone_if type
 *  @return The sixone_if type allocated (zeroed)
 */
sixone_if alloc_sixone_if();

/**
 *  @brief Free a sixone_policy type
 *  @param var The sixone_policy type to free
 *  @todo Implement
 */
void free_sixone_policy(sixone_policy var);

/**
 *  @brief Free a sixone_resolv type
 *  @param var The sixone_resolv type to free
 *  @todo Implement
 */
void free_sixone_resolv(sixone_resolv var);

/**
 *  @brief Free a sixone_settings type
 *  @param var The sixone_settings type to free
 *  @todo Implement
 */
void free_sixone_settings(sixone_settings var);

/**
 *  @brief Free a sixone_net type
 *  @param var The sixone_net type to free
 *  @todo Implement
 */
void free_sixone_net(sixone_net var);

/**
 *  @brief Free a sixone_if type
 *  @param var The sixone_if type to free
 *  @todo Implement
 */
void free_sixone_if(sixone_if var);


/**
 *  @brief Print SixOne configuration from struct
 *  @param settings, Pointer to settings struct
 */
void print_settings(sixone_settings settings);

/**
 *  @brief Print SixOne interface configuration from struct
 *  @param in_if, Pointer to interface struct
 */
void print_if(sixone_if in_if);

/**
 *  @brief Print SixOne network configuration from struct
 *  @param net, Pointer to network struct
 */
void print_net(sixone_net net);


void print_ip_list(ip_list list);

void print_sixone_ip(sixone_ip addr);

/**
 *  @brief Load SixOne configuration from file
 *  @param file absolute path of configuration file.
 *  comes in form of "var=val"
 *  @code 
 *  edge_net=ABC::1
 *  edge_prefix=/64
 *  transit_net=2000::1/64
 *  @endcode
 */
u_int load_settings(u_char* file, sixone_settings settings);

#endif
