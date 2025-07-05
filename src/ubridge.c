/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2015 GNS3 Technologies Inc.
 *
 *   ubridge is free software: you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   ubridge is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>

#ifdef USE_SYSTEM_INIPARSER
#include <iniparser.h>
#else
#include "iniparser/iniparser.h"
#endif

#include "ubridge.h"
#include "parse.h"
#include "pcap_capture.h"
#include "packet_filter.h"
#include "hypervisor.h"
#include "buffer_pool.h"
#include "event_loop.h"
#ifdef __linux__
#include "hypervisor_iol_bridge.h"
#endif

char *config_file = CONFIG_FILE;
pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER;
bridge_t *bridge_list = NULL;
int debug_level = 0;
int hypervisor_mode = 0;

/* Global buffer pool for packet processing */
buffer_pool_t *global_packet_pool = NULL;

/* Event-driven mode configuration */
int event_driven_mode = 1;  /* Enable event-driven mode by default */
event_loop_t *global_event_loop = NULL;

static int bridge_nios(nio_t *rx_nio, nio_t *tx_nio, bridge_t *bridge)
{
  ssize_t bytes_received, bytes_sent;
  unsigned char *pkt;
  int drop_packet;
  int is_pooled_buffer;

  while (1) {
    /* Get packet buffer from global pool */
    pkt = (unsigned char *)get_buffer(global_packet_pool);
    is_pooled_buffer = (pkt != NULL);
    
    if (unlikely(pkt == NULL)) {
        /* Fallback to stack allocation if pool is exhausted */
        static unsigned char fallback_pkt[NIO_MAX_PKT_SIZE];
        pkt = fallback_pkt;
        if (unlikely(debug_level > 1))
            printf("Using fallback buffer allocation on bridge '%s'\n", bridge->name);
    }

    /* receive from the receiving NIO */
    drop_packet = FALSE;
    bytes_received = nio_recv(rx_nio, pkt, NIO_MAX_PKT_SIZE);
    if (unlikely(bytes_received == -1)) {
        /* Return buffer to pool before handling error */
        if (is_pooled_buffer) {
            return_buffer(global_packet_pool, pkt);
        }
        perror("recv");
        if (errno == ECONNREFUSED || errno == ENETDOWN) {
           /* These are recoverable errors, continue with next iteration */
           continue;
        }
        return -1;
    }

    /* Optimize: remove redundant size check - nio_recv already limits this */
    rx_nio->packets_in++;
    rx_nio->bytes_in += bytes_received;

    /* Move debug prints out of hot path using unlikely() */
    if (unlikely(debug_level > 0)) {
        if (rx_nio == bridge->source_nio)
           printf("Received %zd bytes on bridge '%s' (source NIO)\n", bytes_received, bridge->name);
        else
           printf("Received %zd bytes on bridge '%s' (destination NIO)\n", bytes_received, bridge->name);
        if (debug_level > 1)
            dump_packet(stdout, pkt, bytes_received);
    }

    /* filter the packet if there is a filter configured */
    if (unlikely(bridge->filter_chain != NULL && bridge->filter_chain->enabled_count > 0)) {
         /* Use optimized array-based filter chain */
         int filter_result = process_filter_chain(bridge->filter_chain, pkt, bytes_received);
         if (unlikely(filter_result == FILTER_ACTION_DROP)) {
             if (unlikely(debug_level > 0))
                printf("Packet dropped by optimized filter chain on bridge '%s'\n", bridge->name);
             drop_packet = TRUE;
         }
    } else if (unlikely(bridge->packet_filters != NULL)) {
         /* Fallback to legacy linked-list filters for backward compatibility */
         packet_filter_t *filter = bridge->packet_filters;
         packet_filter_t *next;
         while (filter != NULL) {
             if (unlikely(filter->handler(pkt, bytes_received, filter->data) == FILTER_ACTION_DROP)) {
                 if (unlikely(debug_level > 0))
                    printf("Packet dropped by packet filter '%s' on bridge '%s'\n", filter->name, bridge->name);
                 drop_packet = TRUE;
                 break;
             }
             next = filter->next;
             filter = next;
         }
     }

    if (unlikely(drop_packet == TRUE)) {
       /* Return buffer to pool before continuing */
       if (is_pooled_buffer) {
           return_buffer(global_packet_pool, pkt);
       }
       continue;
    }

    /* dump the packet to a PCAP file if capture is activated */
    if (unlikely(bridge->capture != NULL))
        pcap_capture_packet(bridge->capture, pkt, bytes_received);

    /* Prefetch next packet buffer for better cache performance */
    prefetch(pkt + 64);

    /* send what we received to the transmitting NIO */
    bytes_sent = nio_send(tx_nio, pkt, bytes_received);
    if (unlikely(bytes_sent == -1)) {
        /* Return buffer to pool before handling error */
        if (is_pooled_buffer) {
            return_buffer(global_packet_pool, pkt);
        }
        perror("send");

        /* EINVAL can be caused by sending to a blackhole route, this happens if a NIC link status changes */
        if (errno == ECONNREFUSED || errno == ENETDOWN || errno == EINVAL)
           continue;

        /* The linux TAP driver returns EIO if the device is not up.
           From the ubridge side this is not an error, so we should ignore it. */
        if (tx_nio->type == NIO_TYPE_TAP && errno == EIO)
            continue;

        return -1;
    }

    tx_nio->packets_out++;
    tx_nio->bytes_out += bytes_sent;
    
    /* Return buffer to pool after successful processing */
    if (is_pooled_buffer) {
        return_buffer(global_packet_pool, pkt);
    }
  }
  return 0;
}

/* Source NIO thread */
void *source_nio_listener(void *data)
{
  bridge_t *bridge = data;

  printf("Source NIO listener thread for %s has started\n", bridge->name);
  if (bridge->source_nio && bridge->destination_nio)
    /* bridges from the source NIO to the destination NIO */
    if (bridge_nios(bridge->source_nio, bridge->destination_nio, bridge) == -1) {
        fprintf(stderr, "Source NIO listener thread for %s has stopped because of an error: %s \n", bridge->name, strerror(errno));
        exit(EXIT_FAILURE);
    }
  printf("Source NIO listener thread for %s has stopped\n", bridge->name);
  pthread_exit(NULL);
}

/* Destination NIO thread */
void *destination_nio_listener(void *data)
{
  bridge_t *bridge = data;

  printf("Destination NIO listener thread for %s has started\n", bridge->name);
  if (bridge->source_nio && bridge->destination_nio)
      /* bridges from the destination NIO to the source NIO */
      if (bridge_nios(bridge->destination_nio, bridge->source_nio, bridge) == -1) {
         fprintf(stderr, "Destination NIO listener thread for %s has stopped because of an error: %s \n", bridge->name, strerror(errno));
         exit(EXIT_FAILURE);
      }
  printf("Destination NIO listener thread for %s has stopped\n", bridge->name);
  pthread_exit(NULL);
}

static void free_bridges(bridge_t *bridge)
{
  bridge_t *next;

  while (bridge != NULL) {
    if (bridge->name)
       free(bridge->name);
       
    /* Handle cleanup based on mode */
    if (event_driven_mode) {
        /* Event-driven mode: remove from event loop */
        if (global_event_loop) {
            event_loop_remove_bridge(global_event_loop, bridge);
        }
    } else {
        /* Traditional threading mode: cancel and join threads */
        pthread_cancel(bridge->source_tid);
        pthread_join(bridge->source_tid, NULL);
        pthread_cancel(bridge->destination_tid);
        pthread_join(bridge->destination_tid, NULL);
    }
    
    free_nio(bridge->source_nio);
    free_nio(bridge->destination_nio);
    free_pcap_capture(bridge->capture);
    free_packet_filters(bridge->packet_filters);
    if (bridge->filter_chain) {
        destroy_filter_chain(bridge->filter_chain);
    }
    next = bridge->next;
    free(bridge);
    bridge = next;
  }
}

#ifdef __linux__
static void free_iol_bridges(iol_bridge_t *bridge)
{
  iol_bridge_t *next;
  int i;

  while (bridge != NULL) {
    if (bridge->name)
       free(bridge->name);

    close(bridge->iol_bridge_sock);
    unlink(bridge->bridge_sockaddr.sun_path);
    if ((unlock_unix_socket(bridge->sock_lock, bridge->bridge_sockaddr.sun_path)) == -1)
       fprintf(stderr, "failed to unlock %s\n", bridge->bridge_sockaddr.sun_path);

    pthread_cancel(bridge->bridge_tid);
    pthread_join(bridge->bridge_tid, NULL);
    for (i = 0; i < MAX_PORTS; i++) {
        if (bridge->port_table[i].destination_nio != NULL) {
           pthread_cancel(bridge->port_table[i].tid);
           pthread_join(bridge->port_table[i].tid, NULL);
           free_pcap_capture(bridge->port_table[i].capture);
           free_packet_filters(bridge->port_table[i].packet_filters);
           free_nio(bridge->port_table[i].destination_nio);
        }
    }
    free(bridge->port_table);
    next = bridge->next;
    free(bridge);
    bridge = next;
  }
}
#endif

static void create_threads(bridge_t *bridge)
{
    int s;

    while (bridge != NULL) {
       s = pthread_create(&(bridge->source_tid), NULL, &source_nio_listener, bridge);
       if (s != 0)
         handle_error_en(s, "pthread_create");
       s = pthread_create(&(bridge->destination_tid), NULL, &destination_nio_listener, bridge);
       if (s != 0)
         handle_error_en(s, "pthread_create");
       bridge = bridge->next;
    }
}

void ubridge_reset()
{
   free_bridges(bridge_list);
#ifdef __linux__
   free_iol_bridges(iol_bridge_list);
#endif
}

/* Generic signal handler */
void signal_gen_handler(int sig)
{
   switch(sig) {
      case SIGTERM:
      case SIGINT:
         /* CTRL+C has been pressed */
         if (hypervisor_mode) {
            hypervisor_stopsig();
         } else if (event_driven_mode && global_event_loop) {
            /* Stop the event loop */
            event_loop_stop(global_event_loop);
         }
         break;
#ifndef CYGWIN
         /* CTRL+C has been pressed */
      case SIGHUP:
         if (event_driven_mode && global_event_loop) {
            /* For SIGHUP, we want to reload configuration, so stop the event loop */
            event_loop_stop(global_event_loop);
         }
         break;
#endif
      default:
         fprintf(stderr, "Unhandled signal %d\n", sig);
   }
}

int iniparser_error_handler(const char *format, ...)
{
  int ret;
  va_list argptr;
  char *syntax_error = strstr(format, "iniparser: syntax error");

  if(syntax_error != NULL) {
     va_start(argptr, format);
     char *filename = va_arg(argptr, char *);
     int lineno = va_arg(argptr, int);
     ret = fprintf(stderr, "iniparser: syntax error in %s on line %d\n", filename, lineno);
     va_end(argptr);
  }
  else {
     va_start(argptr, format);
     ret = vfprintf(stderr, format, argptr);
     va_end(argptr);
  }

  return ret;
}

static void ubridge(char *hypervisor_ip_address, int hypervisor_tcp_port)
{
   /* Phase 4: Initialize SIMD optimizations */
   if (simd_init() != 0) {
       fprintf(stderr, "Warning: Failed to initialize SIMD optimizations, using fallbacks\n");
   } else {
       const simd_features_t *features = simd_get_features();
       if (debug_level > 0) {
           printf("SIMD features detected: SSE2=%d SSE4.1=%d AVX=%d AVX2=%d AVX512=%d\n",
                  features->has_sse2, features->has_sse4_1, features->has_avx,
                  features->has_avx2, features->has_avx512);
       }
   }

   /* Phase 4: Initialize CPU affinity and NUMA optimization */
   if (cpu_affinity_init() != 0) {
       fprintf(stderr, "Warning: Failed to initialize CPU affinity, continuing without optimization\n");
   } else {
       if (debug_level > 0) {
           cpu_topology_t topology;
           if (get_cpu_topology(&topology) == 0) {           printf("CPU topology: %d cores, %d NUMA nodes detected\n", 
                  topology.num_cpus, topology.num_numa_nodes);
           }
       }
       
       /* Auto-configure CPU affinity for main thread */
       cpu_affinity_config_t *affinity_config = auto_configure_affinity(global_topology, 1);
       if (affinity_config && debug_level > 0) {
           printf("Auto CPU affinity configuration applied\n");
           free(affinity_config);
       }
   }

   /* Initialize global buffer pool for packet processing with NUMA-aware allocation */
   if (init_global_buffer_pool() != 0) {
       fprintf(stderr, "Failed to initialize global buffer pool\n");
       exit(EXIT_FAILURE);
   }

   /* Initialize event-driven mode if enabled */
   if (event_driven_mode) {
       global_event_loop = create_event_loop();
       if (!global_event_loop) {
           fprintf(stderr, "Failed to initialize event loop\n");
           exit(EXIT_FAILURE);
       }
       printf("Event loop initialized for event-driven mode\n");
       
       /* Apply CPU affinity optimization to event loop */
       if (cpu_affinity_is_available()) {
           event_loop_configure_affinity(global_event_loop);
       }
   }

   if (hypervisor_mode) {
       struct sigaction act;

       memset(&act, 0, sizeof(act));
       act.sa_handler = signal_gen_handler;
       act.sa_flags = SA_RESTART;
#ifndef CYGWIN
       sigaction(SIGHUP, &act, NULL);
#endif
       sigaction(SIGTERM, &act, NULL);
       sigaction(SIGINT, &act, NULL);
       sigaction(SIGPIPE, &act, NULL);

      run_hypervisor(hypervisor_ip_address, hypervisor_tcp_port);
      free_bridges(bridge_list);
#ifdef __linux__
      free_iol_bridges(iol_bridge_list);
#endif
   }
   else {
      int sig = 0; /* Initialize signal variable */
      
      if (event_driven_mode) {
         /* Event-driven mode: use signal handlers */
         struct sigaction act;

         memset(&act, 0, sizeof(act));
         act.sa_handler = signal_gen_handler;
         act.sa_flags = SA_RESTART;
#ifndef CYGWIN
         sigaction(SIGHUP, &act, NULL);
#endif
         sigaction(SIGTERM, &act, NULL);
         sigaction(SIGINT, &act, NULL);
         sigaction(SIGPIPE, &act, NULL);
      } else {
         /* Traditional threading mode: use sigwait */
         sigset_t sigset;
         
         sigemptyset(&sigset);
         sigaddset(&sigset, SIGINT);
         sigaddset(&sigset, SIGTERM);
#ifndef CYGWIN
         sigaddset(&sigset, SIGHUP);
#endif
         pthread_sigmask(SIG_BLOCK, &sigset, NULL);
      }

      iniparser_set_error_callback(&iniparser_error_handler);

      while (1) {
         if (!parse_config(config_file, &bridge_list))
            break;
            
         if (event_driven_mode) {
            /* Event-driven mode: register bridges with event loop */
            bridge_t *bridge = bridge_list;
            while (bridge != NULL) {
                if (event_loop_add_bridge(global_event_loop, bridge) != 0) {
                    fprintf(stderr, "Failed to add bridge '%s' to event loop\n", bridge->name);
                    exit(EXIT_FAILURE);
                }
                bridge = bridge->next;
            }
            
            printf("Running in event-driven mode with %zu bridges\n", global_event_loop->bridge_count);
            /* Run the event loop */
            event_loop_run(global_event_loop);
            /* Event loop stopped, check for signals */
            sig = SIGTERM; /* Assume termination when event loop stops */
         } else {
            /* Traditional threading mode */
            sigset_t sigset;
            
            sigemptyset(&sigset);
            sigaddset(&sigset, SIGINT);
            sigaddset(&sigset, SIGTERM);
#ifndef CYGWIN
            sigaddset(&sigset, SIGHUP);
#endif
            
            create_threads(bridge_list);
            sigwait(&sigset, &sig);
         }

         free_bridges(bridge_list);
         bridge_list = NULL;
         if (sig == SIGTERM || sig == SIGINT)
            break;
         printf("Reloading configuration\n");
     }
   }
   
   /* Cleanup */
   if (event_driven_mode && global_event_loop) {
       destroy_event_loop(global_event_loop);
       global_event_loop = NULL;
   }
   
   /* Cleanup global buffer pool before exit */
   cleanup_global_buffer_pool();
   
   /* Phase 4: Cleanup CPU affinity and SIMD */
   cpu_affinity_cleanup();
   simd_cleanup();
}

/* Display all network devices on this host */
static void display_network_devices(void)
{
   char pcap_errbuf[PCAP_ERRBUF_SIZE];
   pcap_if_t *device_list, *device;
   int res;

   printf("Network device list:\n\n");

#ifndef CYGWIN
   res = pcap_findalldevs(&device_list, pcap_errbuf);
#else
   res = pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL, &device_list, pcap_errbuf);
#endif

   if (res < 0) {
      fprintf(stderr, "PCAP: unable to find device list (%s)\n", pcap_errbuf);
      return;
   }

   for(device = device_list; device; device = device->next)
      printf("  %s => %s\n", device->name, device->description ? device->description : "no description");
   printf("\n");

   pcap_freealldevs(device_list);
}

static void print_usage(const char *program_name)
{
  printf("Usage: %s [OPTION]\n"
         "\n"
         "Options:\n"
         "  -h                           : Print this message and exit\n"
         "  -f <file>                    : Specify a INI configuration file (default: %s)\n"
         "  -H [<ip_address>:]<tcp_port> : Run in hypervisor mode\n"
         "  -e                           : Display all available network devices and exit\n"
         "  -E                           : Force enable event-driven mode (default: enabled)\n"
         "  -T                           : Use traditional threading mode (disable event-driven)\n"
         "  -d <level>                   : Debug level\n"
         "  -v                           : Print version and exit\n",
         program_name,
         CONFIG_FILE);
}

int main(int argc, char **argv)
{
  int hypervisor_tcp_port = 0;
  char *hypervisor_ip_address = NULL;
  int opt;
  char *index;
  size_t len;

  setvbuf(stdout, NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IOLBF, 0);

  while ((opt = getopt(argc, argv, "hveETd:f:H:")) != -1) {
    switch (opt) {
      case 'H':
        hypervisor_mode = 1;
        index = strrchr(optarg, ':');
        if (!index) {
           hypervisor_tcp_port = atoi(optarg);
        } else {
           len = index - optarg;
           hypervisor_ip_address = realloc(hypervisor_ip_address, len + 1);

           if (!hypervisor_ip_address) {
              fprintf(stderr, "Unable to set hypervisor IP address!\n");
              exit(EXIT_FAILURE);
           }
           memcpy(hypervisor_ip_address, optarg, len);
           hypervisor_ip_address[len] = '\0';
           hypervisor_tcp_port = atoi(index + 1);
        }
        break;
      case 'E':
        event_driven_mode = 1;
        printf("Event-driven mode explicitly enabled\n");
        break;
      case 'T':
        event_driven_mode = 0;
        printf("Traditional threading mode enabled\n");
        break;
	  case 'v':
	    printf("%s version %s\n", NAME, VERSION);
	    exit(EXIT_SUCCESS);
	  case 'h':
	    print_usage(argv[0]);
	    exit(EXIT_SUCCESS);
	  case 'e':
	    display_network_devices();
	    exit(EXIT_SUCCESS);
	  case 'd':
        debug_level = atoi(optarg);
        break;
	  case 'f':
        config_file = optarg;
        break;
      default:
        exit(EXIT_FAILURE);
	}
  }
  printf("uBridge version %s running with %s\n", VERSION, pcap_lib_version());
  printf("Mode: %s (Phase 4 optimizations enabled)\n", 
         event_driven_mode ? "Event-driven" : "Traditional threading");
  ubridge(hypervisor_ip_address, hypervisor_tcp_port);
  return (EXIT_SUCCESS);
}
