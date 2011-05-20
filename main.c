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

#include "sixonelib/sixonelib.h"

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
  printf("Wake up call ... !!! - Caught signal: %d ... !!\n", sig);
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

  if(argc != 2)
    {
      printf("Usage: %s, <config-file>\n", argv[0]);
      return 2;
      
    }

  DBG_P("START...\n");

  net_settings = alloc_sixone_settings();
  load_settings(argv[1], net_settings);
  
  start_sixone(net_settings);

  return 0;
}


