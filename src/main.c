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

/** @file main.c
 *  @brief Six-One Router
 *  @author Javier Ubillos
 *  @date 2008-08-04
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include "sixonelib.h"

/// @brief DBG enable/disable debug output (should be an #ifdef really)
#define DBG 1
/// @brief DBG_P macro for debug printouts
#define DBG_P if(DBG) printf

#define PROMISC 1
#define NONPROMISC 0

void signalExit() {
	sixone_stop_out_if();
	exit(1);
}

void catchSignal(int sig) {
	printf("Caught signal: %d.\n", sig);
	signal(SIGINT, signalExit );
}

/**
 *  @brief Main loop.
 *  When called from command line, first cfg file, then arguments are devices to listen to.
 */

int main( int argc, char *argv[])
{
	int i;
	
	struct pcap_pkthdr header;
	const u_char *packet;
	pcap_t *sixone_pcap_handles;
	struct ifaddrs *localAddr, *tmpLocalAddr;
	
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	
	///  Array of char* containing arguments to send along packets to pcap_loop-callback (currently not used)
	u_char *pcap_args[2]; 
	
	sixone_settings net_settings;
	
	printf("\n");
	printf(" ____  _       ___                \n");
	printf("/ ___|(_)_  __/ _ \\ _ __   ___    \n");
	printf("\\___ \\| \\ \\/ / | | | '_ \\ / _ \\   \n");
	printf(" ___) | |>  <| |_| | | | |  __/   \n");
	printf("|____/|_/_/\\_\\\\___/|_| |_|\\___|   \n");
	printf("    ____             _                \n");  
	printf("   |  _ \\ ___  _   _| |_ ___ _ __  \n");
	printf("   | |_) / _ \\| | | | __/ _ \\ '__| \n");
	printf("   |  _ < (_) | |_| | ||  __/ | ___   _  \n");
	printf("   |_| \\_\\___/ \\__,_|\\__\\___|_|/ _ \\ / | \n");
	printf("                        \\ \\ / / | | || | \n");
	printf("                         \\ V /| |_| || | \n");
	printf("                          \\_/  \\___(_)_| \n");
	
	signal(SIGINT, catchSignal);
	
	if(argc != 2) {
		printf("Usage: %s, <config-file>\n", argv[0]);
		return 2;
	}
	
	DBG_P("START...\n");
  
	net_settings = alloc_sixone_settings();
	load_settings(argv[1], net_settings);
  
	start_sixone(net_settings);
  
	return 0;
}


