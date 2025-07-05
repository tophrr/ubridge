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

#ifndef EVENT_LOOP_H_
#define EVENT_LOOP_H_

#include <sys/types.h>
#include <stdint.h>
#include <pthread.h>

#ifdef __linux__
#include <sys/epoll.h>
#endif

#ifdef __FreeBSD__
#include <sys/event.h>
#endif

#include "ubridge.h"
#include "buffer_pool.h"

/* Event loop configuration constants */
#define MAX_EVENTS_PER_LOOP     1024    /* Maximum events per epoll_wait call */
#define DEFAULT_BATCH_SIZE      32      /* Default packet batch size */
#define MAX_BATCH_SIZE          256     /* Maximum packet batch size */
#define EVENT_LOOP_TIMEOUT_MS   100     /* Event loop timeout in milliseconds */

/* Event types for the event loop */
typedef enum {
    EVENT_TYPE_READ,
    EVENT_TYPE_WRITE,
    EVENT_TYPE_ERROR,
    EVENT_TYPE_CLOSE
} event_type_t;

/* Forward declarations */
typedef struct event_loop event_loop_t;
typedef struct event_handler event_handler_t;
typedef struct packet_batch packet_batch_t;

/* Event callback function type */
typedef int (*event_callback_t)(event_loop_t *loop, int fd, event_type_t event_type, void *data);

/* Event handler structure */
struct event_handler {
    int fd;                         /* File descriptor */
    event_type_t events;            /* Monitored event types */
    event_callback_t callback;      /* Event callback function */
    void *data;                     /* User data */
    bridge_t *bridge;               /* Associated bridge */
    nio_t *nio;                     /* Associated NIO */
    struct event_handler *next;     /* Next handler in list */
};

/* Packet batch structure for efficient packet processing */
struct packet_batch {
    void **buffers;                 /* Array of packet buffers */
    size_t *lengths;                /* Array of packet lengths */
    struct sockaddr_storage *addrs; /* Array of source addresses */
    socklen_t *addr_lens;           /* Array of address lengths */
    int count;                      /* Current number of packets in batch */
    int capacity;                   /* Maximum capacity of batch */
    bridge_t *bridge;               /* Associated bridge */
    nio_t *source_nio;              /* Source NIO */
    nio_t *destination_nio;         /* Destination NIO */
};

/* Event loop statistics */
typedef struct event_loop_stats {
    uint64_t total_events;          /* Total events processed */
    uint64_t read_events;           /* Read events processed */
    uint64_t write_events;          /* Write events processed */
    uint64_t error_events;          /* Error events processed */
    uint64_t packets_batched;       /* Total packets processed in batches */
    uint64_t batches_processed;     /* Total batches processed */
    uint64_t zero_copy_transfers;   /* Zero-copy transfers performed */
    double avg_batch_size;          /* Average batch size */
    double avg_loop_time_us;        /* Average loop iteration time */
} event_loop_stats_t;

/* Main event loop structure */
struct event_loop {
    /* Core event loop data */
    int running;                    /* Event loop running flag */
    int epoll_fd;                   /* epoll file descriptor (Linux) */
    int kqueue_fd;                  /* kqueue file descriptor (BSD) */
    
    /* Event management */
    void *events;                   /* Event array (platform-specific) */
    int max_events;                 /* Maximum events per iteration */
    int timeout_ms;                 /* Event loop timeout */
    
    /* Handler management */
    event_handler_t *handlers;      /* List of event handlers */
    int handler_count;              /* Number of registered handlers */
    
    /* Bridge management */
    bridge_t **bridges;             /* Array of bridges */
    size_t bridge_count;            /* Number of bridges */
    size_t bridge_capacity;         /* Bridge array capacity */
    
    /* Packet batching */
    packet_batch_t *batch_pool;     /* Pool of packet batches */
    int batch_size;                 /* Default batch size */
    int enable_batching;            /* Enable packet batching */
    
    /* Performance tuning */
    int enable_zero_copy;           /* Enable zero-copy optimizations */
    int worker_threads;             /* Number of worker threads */
    pthread_t *workers;             /* Worker thread pool */
    
    /* Statistics and monitoring */
    event_loop_stats_t stats;       /* Performance statistics */
    pthread_mutex_t stats_lock;     /* Statistics mutex */
    
    /* Configuration */
    buffer_pool_t *buffer_pool;     /* Buffer pool for packets */
};

/* Event loop management functions */
event_loop_t *create_event_loop(void);
void destroy_event_loop(event_loop_t *loop);
int event_loop_run(event_loop_t *loop);
void event_loop_stop(event_loop_t *loop);

/* Bridge management */
int event_loop_add_bridge(event_loop_t *loop, bridge_t *bridge);
int event_loop_remove_bridge(event_loop_t *loop, bridge_t *bridge);
int event_loop_update_bridge(event_loop_t *loop, bridge_t *bridge);

/* Event handler management */
int add_event_handler(event_loop_t *loop, int fd, event_type_t events, 
                     event_callback_t callback, void *data);
int remove_event_handler(event_loop_t *loop, int fd);
int modify_event_handler(event_loop_t *loop, int fd, event_type_t events);

/* Packet batching functions */
packet_batch_t *create_packet_batch(int capacity);
void destroy_packet_batch(packet_batch_t *batch);
int add_packet_to_batch(packet_batch_t *batch, void *buffer, size_t length, 
                       struct sockaddr *addr, socklen_t addr_len);
int process_packet_batch(event_loop_t *loop, packet_batch_t *batch);
void clear_packet_batch(packet_batch_t *batch);

/* Zero-copy operations */
#ifdef __linux__
int zero_copy_transfer(int in_fd, int out_fd, size_t count);
int setup_packet_mmap(nio_t *nio);
#endif

/* Performance monitoring */
void get_event_loop_stats(event_loop_t *loop, event_loop_stats_t *stats);
void reset_event_loop_stats(event_loop_t *loop);
void print_event_loop_stats(event_loop_t *loop);

/* Configuration functions */
int configure_event_loop(event_loop_t *loop, const char *config_section);
int set_event_loop_batch_size(event_loop_t *loop, int batch_size);
int set_event_loop_timeout(event_loop_t *loop, int timeout_ms);
int enable_event_loop_zero_copy(event_loop_t *loop, int enable);

/* Platform-specific implementations */
#ifdef __linux__
int epoll_manager_init(event_loop_t *loop);
int epoll_manager_add_fd(event_loop_t *loop, int fd, uint32_t events, void *data);
int epoll_manager_modify_fd(event_loop_t *loop, int fd, uint32_t events, void *data);
int epoll_manager_remove_fd(event_loop_t *loop, int fd);
int epoll_manager_wait(event_loop_t *loop, int timeout_ms);
void epoll_manager_cleanup(event_loop_t *loop);
#endif

#ifdef __FreeBSD__
int kqueue_manager_init(event_loop_t *loop);
int kqueue_manager_add_fd(event_loop_t *loop, int fd, int16_t filter, void *data);
int kqueue_manager_remove_fd(event_loop_t *loop, int fd, int16_t filter);
int kqueue_manager_wait(event_loop_t *loop, int timeout_ms);
void kqueue_manager_cleanup(event_loop_t *loop);
#endif

/* Utility functions */
const char *event_type_to_string(event_type_t event_type);
void log_event_loop_error(const char *function, const char *message);

/* Default event callbacks */
int bridge_read_callback(event_loop_t *loop, int fd, event_type_t event_type, void *data);
int bridge_write_callback(event_loop_t *loop, int fd, event_type_t event_type, void *data);
int bridge_error_callback(event_loop_t *loop, int fd, event_type_t event_type, void *data);

#endif /* !EVENT_LOOP_H_ */
