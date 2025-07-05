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

#ifndef UBRIDGE_H_
#define UBRIDGE_H_

#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

#ifdef CYGWIN
/* Needed for pcap_open() flags */
#define HAVE_REMOTE
#endif

#include <pcap.h>

#include "nio.h"
#include "packet_filter.h"
#include "buffer_pool.h"
#include "buffer_pool.h"

#define NAME          "ubridge"
#define VERSION       "0.9.19"
#define CONFIG_FILE   "ubridge.ini"

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE  1
#endif

#define handle_error_en(en, msg) \
        do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#define perror(msg) \
        do { int en = errno; perror(msg); errno = en; } while (0)

/* Branch prediction macros for performance optimization */
#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#define prefetch(x)     __builtin_prefetch(x, 0, 3)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#define prefetch(x)     do { } while (0)
#endif

typedef struct {
    pcap_t *fd;
    pcap_dumper_t *dumper;
    pthread_mutex_t lock;
} pcap_capture_t;

/* Cache-aligned bridge structure for optimal performance */
typedef struct bridge {
  /* Hot data - frequently accessed fields grouped together */
  int running;                          /* Bridge state */
  nio_t *source_nio;                   /* Source NIO pointer */
  nio_t *destination_nio;              /* Destination NIO pointer */
  
  /* Filter chain - optimized for Phase 2 */
  packet_filter_t *packet_filters;     /* Legacy linked list (backward compatibility) */
  filter_chain_t *filter_chain;        /* Optimized array-based chain */
  
  /* Performance monitoring */
  uint64_t packets_processed;
  uint64_t bytes_processed;
  uint64_t packets_dropped;
  uint64_t last_activity_time;
  
  /* Threading data */
  pthread_t source_tid;
  pthread_t destination_tid;
  
  /* Less frequently accessed data */
  char *name;                          /* Bridge name */
  pcap_capture_t *capture;             /* PCAP capture */
  struct bridge *next;                 /* Next bridge in list */
  
  /* Padding to align to cache line */
  char padding[64];
} __attribute__((aligned(64))) bridge_t;

extern bridge_t *bridge_list;
extern pthread_mutex_t global_lock;
extern int debug_level;

/* Global buffer pool for packet processing */
extern buffer_pool_t *global_packet_pool;

/* Event-driven mode configuration */
extern int event_driven_mode;
extern struct event_loop *global_event_loop;

/* Buffer pool management functions */
int init_global_buffer_pool(void);
void cleanup_global_buffer_pool(void);

void ubridge_reset();
void *source_nio_listener(void *data);
void *destination_nio_listener(void *data);

#endif /* !UBRIDGE_H_ */
