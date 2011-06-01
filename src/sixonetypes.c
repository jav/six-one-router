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

/** @file sixonelib/sixonetypes.c
 *  @brief Six-One Router Types
 *  @author Javier Ubillos
 *  @date 2008-08-06
 */

#include "sixonetypes.h"

#include <sys/types.h>
#include <sys/socket.h> // required by ip6.h
#include <netinet/in.h> // required by ip6.h
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


/// @brief DBG enable/disable debug output (should be an #ifdef really)
#define DBG 1
/// @brief DBG_P macro for debug printouts
#define DBG_P if(DBG) printf

sixone_ip alloc_sixone_ip()
{
  return (sixone_ip) calloc( 1 , sizeof(struct sixone_ip_) );
}

ip_list alloc_ip_list()
{
  return (ip_list) calloc( 1 , sizeof(struct ip_list_) );
}

sixone_policy alloc_sixone_policy()
{
  return (sixone_policy) calloc( 1 , sizeof(struct sixone_policy_) );
}

sixone_resolv alloc_sixone_resolv()
{
  return (sixone_resolv) calloc( 1 , sizeof(struct sixone_resolv_) );
}

sixone_settings alloc_sixone_settings()
{
  sixone_settings ret = (sixone_settings) calloc( 1 , sizeof(struct sixone_settings_) );
  ret->resolv = alloc_sixone_resolv();
  ret->policy = alloc_sixone_policy();
  return ret;
}

sixone_if alloc_sixone_if()
{
  return (sixone_if) calloc(1, sizeof(struct sixone_if_)) ;
}

sixone_net alloc_sixone_net()
{
  return (sixone_net) calloc(1, sizeof(struct sixone_net_)) ;
}

void free_ip_list(ip_list iplist)
{
  return;
}

void free_sixone_policy(sixone_policy var)
{
  return free(var);
}

void free_sixone_resolv(sixone_resolv var)
{
  return free(var);
}

void free_sixone_settings(sixone_settings var)
{
  int i;
  for(i = 0; i < var->if_c; i++)
    {
      free_sixone_if( var->if_v[i] );
    }
  
  free_sixone_policy(var->policy);
  free_sixone_resolv(var->resolv);
  free (var);

  return;
}

void free_sixone_if(sixone_if var)
{
  int i;
  //  for( i=0; i < var->if_c ; i++)
  //free_sixone_net(var->if_v[i]);

  //free(var);
  return;
}

void free_sixone_net(sixone_net var)
{
  //free(var->addr);
  //free(var);
  return;
}

void print_settings(sixone_settings settings)
{
  int i;
  printf("Settings: [%u]\n", settings->if_c);
  for( i = 0; i < settings->if_c; ++i)
    {
      print_if( settings->if_v[i] );
    }
  return;
}

void print_if(sixone_if in_if)
{
  int i;
  printf("\tif: (%s) [%u]\n", in_if->if_name, in_if->net_c);
  for( i = 0; i < in_if->net_c; ++i)
    {
      print_net(in_if->net_v[i]);
    }
    
  return;
}

void print_ip_list(ip_list list)
{
  int i = 0;


  while(list != NULL)    {
    printf("[%i] ");
    print_sixone_ip(list->ip);
    list = list->next;    
  }

  return;
}

void print_sixone_ip(sixone_ip addr)
{
  char ip_str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &addr->ip, ip_str, sizeof(ip_str));
  printf("%s/%d", ip_str, addr->pfx);
  return;
}

void print_net(sixone_net net)
{
  char ip[INET6_ADDRSTRLEN];
  char gw[INET6_ADDRSTRLEN];

  if(net->edge) {
    inet_ntop(AF_INET6, &net->addr->ip, ip, sizeof(ip));
    printf("\t\t[Edge]");
    printf("net: %s/%u\n", ip, net->addr->pfx);
  }
  else {
    inet_ntop(AF_INET6, &net->addr->ip, ip, sizeof(ip));
    inet_ntop(AF_INET6, net->gw, gw, sizeof(gw));
    printf("\t\t[Transit]");
    printf("net: %s/%u -> %s\n", ip, net->addr->pfx, gw);
  }


  return;
}

u_int load_settings(u_char* file, sixone_settings settings)
{
  FILE* _fh;
  u_char _string[256];
  u_char _ip[INET6_ADDRSTRLEN], _gw[INET6_ADDRSTRLEN];
  u_char* _str, _pfx;
  int i;
  sixone_if  **_if_v, _if;
  u_int _if_c;
  sixone_net **_net_v, _net;
  u_int _net_c;
  // *_vector which points to (*settings)->edgev
  // which is of type struct sixone_net*

  DBG_P("%s:%d : load_config(%s)\n", __FILE__, __LINE__, file);

  if( NULL == ( _fh = fopen( file, "r") ) )
    {
      printf("Cannot open file. %s\n", file);
      exit (1);
    }

  // Assuming settings is new and empty

    while( NULL != fgets(_string, 256, _fh) )
      {
	_str = _string;
	// fast forward spaces
	while( isspace(*_str) && '\n' != *_str )
	  ++_str;

	if('#' == *_str || '\n' == *_str)
	  {
	    continue;
	  }
	else if( '[' == *_str)
	  {
	    //DBG_P("%s:%d interface %s\n", __FILE__, __LINE__, _str);
	    _if_v = &settings->if_v;
	    _if_c = settings->if_c ;

	    *_if_v =(sixone_if*) realloc( *_if_v, sizeof(sixone_if) * (_if_c + 1) );

	    if(NULL == *_if_v)
	      {
		printf("Could not realloc()\n");
		exit(1);
	      }
	    (*_if_v)[_if_c] = alloc_sixone_if();
	    if( NULL == (*_if_v)[_if_c] )
	      {
		printf("%s:%d : Could not (*_if_v)[%d] = alloc_sixone_if()\n", __FILE__, __LINE__, _if_c);
		exit(1);
	      }
	    (*_if_v)[_if_c]->if_name = (u_char*)malloc(strlen(_str) - strlen("[]"));

	    memset((*_if_v)[_if_c]->if_name, 0, strlen(_str) - strlen("[]"));
	    memcpy((*_if_v)[_if_c]->if_name, (_str+1), strlen(_str) - strlen("[]") - 1 );
	    settings->if_c++;

	    //print_settings(settings);
	  }
	else if('E' == toupper(*_str) || 'T' == toupper(*_str) )
	  {
	    //DBG_P("%s:%d net\n", __FILE__, __LINE__);
	    _if_c = settings->if_c;
	    _if = settings->if_v[_if_c -1];

	    _net_c = _if->net_c;
	    _net_v = &_if->net_v;

	    *_net_v =
	      (sixone_net*) realloc( *_net_v, 
				     sizeof(sixone_net) * (_net_c +1) );

	    if(NULL == *_net_v)
	      {
		printf("Could not realloc()\n");
	      }

	    _net = (*_net_v)[_net_c] = alloc_sixone_net();
	    _net->addr = alloc_sixone_ip();

	    _net->edge = ( 'E' == toupper(*_str) );
	    
	    _str = (u_char *)strchr(_str, '=') +1;

		    
	    // is it an edge net?
	    if(_net->edge) { 

			sscanf((const char *)_str, "%s %d\n", _ip, &_net->addr->pfx);
	      inet_pton(AF_INET6, (char const *)_ip, &_net->addr->ip);
	      _net->gw = NULL;
	      //DBG_P("%s:%d net : edge (%s)/(%d)\n", __FILE__, __LINE__, _ip, _net->addr->pfx);
	    }
	    else {
			sscanf((const char *)_str, "%s %d %s", _ip, &_net->addr->pfx, _gw);
			inet_pton(AF_INET6, (char const *)_ip, &_net->addr->ip);
	      _net->gw = malloc(sizeof(struct in6_addr ));
	      inet_pton(AF_INET6, (char const *)_gw, _net->gw);
	      //DBG_P("%s:%d net : transit (%s)/(%d) -> %s\n", __FILE__, __LINE__, _ip, _net->addr->pfx, _gw);
	    }

	    _if->net_c++;
	  }
	else
	  DBG_P("%s:%d Undetermined contents: %s\n", __FILE__, __LINE__, _str);

      }

  
  fclose(_fh);
  //DBG_P("%s:%d : load_config() fclose & return (void) \n", __FILE__, __LINE__);

  //persistent storage
 

  return 0;
}
