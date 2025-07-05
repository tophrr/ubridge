/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2017 GNS3 Technologies Inc.
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

#ifndef FILTER_H_
#define FILTER_H_

#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>

/* Branch prediction macros (duplicated from ubridge.h to avoid circular dependency) */
#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

/* Maximum number of filters per bridge (for array-based optimization) */
#define MAX_FILTERS_PER_BRIDGE 16

enum {
    FILTER_TYPE_FREQUENCY_DROP = 1,
    FILTER_TYPE_PACKET_LOSS,
    FILTER_TYPE_DELAY,
    FILTER_TYPE_CORRUPT,
    FILTER_TYPE_BPF,
};

enum {
   FILTER_ACTION_DROP = 0,
   FILTER_ACTION_PASS,
   FILTER_ACTION_ALTER,
   FILTER_ACTION_DUPLICATE,
};

/* Optimized packet filter structure */
typedef struct packet_filter {
   uint32_t type;
   char *name;
   void *data;
   int (*setup)(void **opt, int argc, char *argv[]);
   int (*handler)(void *pkt, size_t len, void *opt);
   void (*free)(void **opt);
   struct packet_filter *next;
   
   /* Performance optimization fields */
   uint32_t call_count;        /* Number of times filter was called */
   uint32_t drop_count;        /* Number of packets dropped */
   uint64_t total_time_ns;     /* Total time spent in this filter */
   uint8_t priority;           /* Filter priority (0=highest, 255=lowest) */
   uint8_t flags;              /* Filter flags for optimization */
} __attribute__((aligned(64))) packet_filter_t; /* Cache line aligned */

/* Filter flags */
#define FILTER_FLAG_ENABLED     0x01
#define FILTER_FLAG_STATELESS   0x02    /* Filter has no state, can be cached */
#define FILTER_FLAG_FAST        0x04    /* Filter is very fast, no timing needed */

/* Array-based filter chain for better cache performance */
typedef struct filter_chain {
    packet_filter_t *filters[MAX_FILTERS_PER_BRIDGE];
    int (*fast_handlers[MAX_FILTERS_PER_BRIDGE])(void *pkt, size_t len, void *opt);
    void *fast_data[MAX_FILTERS_PER_BRIDGE];
    uint8_t count;
    uint8_t enabled_count;
    uint16_t version;           /* Incremented when chain changes */
} filter_chain_t;

/* Traditional linked-list API (for backward compatibility) */
int add_packet_filter(packet_filter_t **packet_filters, char *filter_name, char *filter_type, int argc, char *argv[]);
packet_filter_t *find_packet_filter(packet_filter_t *packet_filters, char *filter_name);
int delete_packet_filter(packet_filter_t **packet_filters, char *filter_name);
void free_packet_filters(packet_filter_t *filter);

/* Optimized array-based filter chain API */
filter_chain_t *create_filter_chain(void);
void destroy_filter_chain(filter_chain_t *chain);
int add_filter_to_chain(filter_chain_t *chain, packet_filter_t *filter);
int remove_filter_from_chain(filter_chain_t *chain, const char *filter_name);
void enable_filter_in_chain(filter_chain_t *chain, const char *filter_name);
void disable_filter_in_chain(filter_chain_t *chain, const char *filter_name);

/* Fast packet processing */
int process_filter_chain(filter_chain_t *chain, void *pkt, size_t len);

/* Convert linked list to array-based chain */
filter_chain_t *convert_to_filter_chain(packet_filter_t *linked_filters);

/* Performance monitoring */
void get_filter_stats(packet_filter_t *filter, uint32_t *calls, uint32_t *drops, double *avg_time_us);
void reset_filter_stats(packet_filter_t *filter);

#endif /* !FILTER_H_ */
