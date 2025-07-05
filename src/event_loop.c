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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#endif

#ifdef __FreeBSD__
#include <sys/event.h>
#endif

#include "event_loop.h"
#include "ubridge.h"
#include "packet_filter.h"
#include "pcap_capture.h"
#include "nio.h"
#include "packet_filter.h"
#include "cpu_affinity.h"
#include "simd_optimizations.h"

/* Create a new event loop */
event_loop_t *create_event_loop(void)
{
    event_loop_t *loop;
    
    loop = malloc(sizeof(event_loop_t));
    if (!loop) {
        log_event_loop_error("create_event_loop", "Failed to allocate memory");
        return NULL;
    }
    
    memset(loop, 0, sizeof(event_loop_t));
    
    /* Initialize default configuration */
    loop->max_events = MAX_EVENTS_PER_LOOP;
    loop->timeout_ms = EVENT_LOOP_TIMEOUT_MS;
    loop->batch_size = DEFAULT_BATCH_SIZE;
    loop->enable_batching = 1;
    loop->enable_zero_copy = 1;
    loop->worker_threads = 0; /* Auto-detect */
    
    /* Initialize platform-specific event mechanism */
#ifdef __linux__
    if (epoll_manager_init(loop) < 0) {
        free(loop);
        return NULL;
    }
#elif defined(__FreeBSD__)
    if (kqueue_manager_init(loop) < 0) {
        free(loop);
        return NULL;
    }
#else
    log_event_loop_error("create_event_loop", "Unsupported platform");
    free(loop);
    return NULL;
#endif
    
    /* Allocate bridge array */
    loop->bridge_capacity = 16; /* Initial capacity */
    loop->bridges = malloc(sizeof(bridge_t*) * loop->bridge_capacity);
    if (!loop->bridges) {
        destroy_event_loop(loop);
        return NULL;
    }
    
    /* Create packet batch pool */
    loop->batch_pool = create_packet_batch(loop->batch_size);
    if (!loop->batch_pool) {
        destroy_event_loop(loop);
        return NULL;
    }
    
    /* Initialize statistics mutex */
    if (pthread_mutex_init(&loop->stats_lock, NULL) != 0) {
        destroy_event_loop(loop);
        return NULL;
    }
    
    /* Use global buffer pool */
    loop->buffer_pool = global_packet_pool;
    
    /* Set up zero-copy buffers if enabled */
    if (setup_zero_copy_buffers(loop) < 0) {
        if (debug_level > 0) {
            printf("Warning: Zero-copy buffer setup failed, continuing without zero-copy\n");
        }
        loop->enable_zero_copy = 0;
    }
    
    if (debug_level > 0) {
        printf("Created event loop: max_events=%d, batch_size=%d, zero_copy=%s\n",
               loop->max_events, loop->batch_size, 
               loop->enable_zero_copy ? "enabled" : "disabled");
    }
    
    return loop;
}

/* Destroy event loop */
void destroy_event_loop(event_loop_t *loop)
{
    if (!loop) return;
    
    /* Stop the event loop */
    event_loop_stop(loop);
    
    /* Clean up platform-specific resources */
#ifdef __linux__
    epoll_manager_cleanup(loop);
#elif defined(__FreeBSD__)
    kqueue_manager_cleanup(loop);
#endif
    
    /* Free event handlers */
    event_handler_t *handler = loop->handlers;
    while (handler) {
        event_handler_t *next = handler->next;
        free(handler);
        handler = next;
    }
    
    /* Free bridges array */
    if (loop->bridges) {
        free(loop->bridges);
    }
    
    /* Free packet batch pool */
    if (loop->batch_pool) {
        destroy_packet_batch(loop->batch_pool);
    }
    
    /* Clean up worker threads */
    if (loop->workers) {
        free(loop->workers);
    }
    
    /* Destroy statistics mutex */
    pthread_mutex_destroy(&loop->stats_lock);
    
    free(loop);
    
    if (debug_level > 0) {
        printf("Destroyed event loop\n");
    }
}

/* Main event loop */
int event_loop_run(event_loop_t *loop)
{
    struct timespec start_time, end_time;
    int events_processed;
    
    if (!loop) {
        return -1;
    }
    
    loop->running = 1;
    
    if (debug_level > 0) {
        printf("Starting event loop with %zu bridges\n", loop->bridge_count);
    }
    
    while (loop->running) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        
        /* Wait for events */
#ifdef __linux__
        events_processed = epoll_manager_wait(loop, loop->timeout_ms);
#elif defined(__FreeBSD__)
        events_processed = kqueue_manager_wait(loop, loop->timeout_ms);
#else
        events_processed = -1;
#endif
        
        if (events_processed < 0) {
            if (errno == EINTR) {
                continue; /* Interrupted by signal */
            }
            log_event_loop_error("event_loop_run", "Event wait failed");
            break;
        }
        
        /* Update statistics */
        pthread_mutex_lock(&loop->stats_lock);
        loop->stats.total_events += events_processed;
        
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        double loop_time = (end_time.tv_sec - start_time.tv_sec) * 1000000.0 +
                          (end_time.tv_nsec - start_time.tv_nsec) / 1000.0;
        
        /* Update average loop time using exponential moving average */
        if (loop->stats.avg_loop_time_us == 0) {
            loop->stats.avg_loop_time_us = loop_time;
        } else {
            loop->stats.avg_loop_time_us = 0.9 * loop->stats.avg_loop_time_us + 0.1 * loop_time;
        }
        
        pthread_mutex_unlock(&loop->stats_lock);
        
        /* Debug output for high loop times */
        if (unlikely(debug_level > 1 && loop_time > 1000.0)) {
            printf("Event loop iteration took %.2f us (%d events)\n", loop_time, events_processed);
        }
    }
    
    if (debug_level > 0) {
        printf("Event loop stopped\n");
        print_event_loop_stats(loop);
    }
    
    return 0;
}

/* Stop event loop */
void event_loop_stop(event_loop_t *loop)
{
    if (loop) {
        loop->running = 0;
    }
}

/* Add bridge to event loop */
int event_loop_add_bridge(event_loop_t *loop, bridge_t *bridge)
{
    if (!loop || !bridge) {
        return -1;
    }
    
    /* Resize bridge array if needed */
    if (loop->bridge_count >= loop->bridge_capacity) {
        size_t new_capacity = loop->bridge_capacity * 2;
        bridge_t **new_bridges = realloc(loop->bridges, sizeof(bridge_t*) * new_capacity);
        if (!new_bridges) {
            log_event_loop_error("event_loop_add_bridge", "Failed to resize bridge array");
            return -1;
        }
        loop->bridges = new_bridges;
        loop->bridge_capacity = new_capacity;
    }
    
    /* Add bridge to array */
    loop->bridges[loop->bridge_count++] = bridge;
    
    /* Add event handlers for bridge NIOs */
    if (bridge->source_nio && bridge->source_nio->dptr) {
        int fd = *(int*)bridge->source_nio->dptr; /* Assumes fd is stored as int */
        add_event_handler(loop, fd, EVENT_TYPE_READ, bridge_read_callback, bridge);
    }
    
    if (bridge->destination_nio && bridge->destination_nio->dptr) {
        int fd = *(int*)bridge->destination_nio->dptr;
        add_event_handler(loop, fd, EVENT_TYPE_WRITE, bridge_write_callback, bridge);
    }
    
    if (debug_level > 0) {
        printf("Added bridge '%s' to event loop\n", bridge->name);
    }
    
    return 0;
}

/* Remove bridge from event loop */
int event_loop_remove_bridge(event_loop_t *loop, bridge_t *bridge)
{
    if (!loop || !bridge) {
        return -1;
    }
    
    /* Find and remove bridge from array */
    for (size_t i = 0; i < loop->bridge_count; i++) {
        if (loop->bridges[i] == bridge) {
            /* Shift remaining bridges */
            memmove(&loop->bridges[i], &loop->bridges[i + 1], 
                   (loop->bridge_count - i - 1) * sizeof(bridge_t*));
            loop->bridge_count--;
            
            /* Remove event handlers for bridge NIOs */
            if (bridge->source_nio && bridge->source_nio->dptr) {
                int fd = *(int*)bridge->source_nio->dptr;
                remove_event_handler(loop, fd);
            }
            
            if (bridge->destination_nio && bridge->destination_nio->dptr) {
                int fd = *(int*)bridge->destination_nio->dptr;
                remove_event_handler(loop, fd);
            }
            
            if (debug_level > 0) {
                printf("Removed bridge '%s' from event loop\n", bridge->name);
            }
            
            return 0;
        }
    }
    
    return -1; /* Bridge not found */
}

/* Add event handler */
int add_event_handler(event_loop_t *loop, int fd, event_type_t events, 
                     event_callback_t callback, void *data)
{
    if (!loop || fd < 0 || !callback) {
        return -1;
    }
    
    /* Create new handler */
    event_handler_t *handler = malloc(sizeof(event_handler_t));
    if (!handler) {
        log_event_loop_error("add_event_handler", "Failed to allocate handler");
        return -1;
    }
    
    handler->fd = fd;
    handler->events = events;
    handler->callback = callback;
    handler->data = data;
    handler->bridge = (bridge_t*)data; /* Assumes data is bridge pointer */
    handler->nio = NULL; /* Will be set by caller if needed */
    handler->next = loop->handlers;
    
    loop->handlers = handler;
    loop->handler_count++;
    
    /* Set non-blocking mode for the file descriptor */
    int flags = fcntl(fd, F_GETFL);
    if (flags != -1) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    
    /* Add to platform-specific event mechanism */
#ifdef __linux__
    uint32_t epoll_events = 0;
    if (events & EVENT_TYPE_READ) epoll_events |= EPOLLIN;
    if (events & EVENT_TYPE_WRITE) epoll_events |= EPOLLOUT;
    epoll_events |= EPOLLET; /* Edge-triggered */
    
    if (epoll_manager_add_fd(loop, fd, epoll_events, handler) < 0) {
        free(handler);
        return -1;
    }
#elif defined(__FreeBSD__)
    if (events & EVENT_TYPE_READ) {
        if (kqueue_manager_add_fd(loop, fd, EVFILT_READ, handler) < 0) {
            free(handler);
            return -1;
        }
    }
    if (events & EVENT_TYPE_WRITE) {
        if (kqueue_manager_add_fd(loop, fd, EVFILT_WRITE, handler) < 0) {
            free(handler);
            return -1;
        }
    }
#endif
    
    if (debug_level > 1) {
        printf("Added event handler for fd %d, events %d\n", fd, events);
    }
    
    return 0;
}

/* Remove event handler */
int remove_event_handler(event_loop_t *loop, int fd)
{
    if (!loop || fd < 0) {
        return -1;
    }
    
    /* Find and remove handler */
    event_handler_t **current = &loop->handlers;
    while (*current) {
        if ((*current)->fd == fd) {
            event_handler_t *handler = *current;
            *current = handler->next;
            
            /* Remove from platform-specific event mechanism */
#ifdef __linux__
            epoll_manager_remove_fd(loop, fd);
#elif defined(__FreeBSD__)
            kqueue_manager_remove_fd(loop, fd, EVFILT_READ);
            kqueue_manager_remove_fd(loop, fd, EVFILT_WRITE);
#endif
            
            free(handler);
            loop->handler_count--;
            
            if (debug_level > 1) {
                printf("Removed event handler for fd %d\n", fd);
            }
            
            return 0;
        }
        current = &(*current)->next;
    }
    
    return -1; /* Handler not found */
}

/* Configuration functions */
int set_event_loop_batch_size(event_loop_t *loop, int batch_size)
{
    if (!loop || batch_size <= 0 || batch_size > MAX_BATCH_SIZE) {
        return -1;
    }
    
    loop->batch_size = batch_size;
    
    /* Recreate batch pool with new size */
    if (loop->batch_pool) {
        destroy_packet_batch(loop->batch_pool);
    }
    
    loop->batch_pool = create_packet_batch(batch_size);
    if (!loop->batch_pool) {
        log_event_loop_error("set_event_loop_batch_size", "Failed to create new batch pool");
        return -1;
    }
    
    if (debug_level > 0) {
        printf("Event loop batch size set to %d\n", batch_size);
    }
    
    return 0;
}

int set_event_loop_timeout(event_loop_t *loop, int timeout_ms)
{
    if (!loop || timeout_ms < 0) {
        return -1;
    }
    
    loop->timeout_ms = timeout_ms;
    
    if (debug_level > 0) {
        printf("Event loop timeout set to %d ms\n", timeout_ms);
    }
    
    return 0;
}

int enable_event_loop_zero_copy(event_loop_t *loop, int enable)
{
    if (!loop) {
        return -1;
    }
    
    loop->enable_zero_copy = enable ? 1 : 0;
    
    if (debug_level > 0) {
        printf("Event loop zero-copy %s\n", enable ? "enabled" : "disabled");
    }
    
    return 0;
}

int configure_event_loop(event_loop_t *loop, const char *config_section)
{
    /* This function could be enhanced to read from configuration files */
    /* For now, it's a placeholder that returns success */
    if (!loop) {
        return -1;
    }
    
    if (debug_level > 0) {
        printf("Event loop configured from section: %s\n", config_section ? config_section : "default");
    }
    
    return 0;
}

/* Get event loop statistics */
void get_event_loop_stats(event_loop_t *loop, event_loop_stats_t *stats)
{
    if (!loop || !stats) return;
    
    pthread_mutex_lock(&loop->stats_lock);
    *stats = loop->stats;
    pthread_mutex_unlock(&loop->stats_lock);
}

/* Reset event loop statistics */
void reset_event_loop_stats(event_loop_t *loop)
{
    if (!loop) return;
    
    pthread_mutex_lock(&loop->stats_lock);
    memset(&loop->stats, 0, sizeof(event_loop_stats_t));
    pthread_mutex_unlock(&loop->stats_lock);
}

/* Print event loop statistics */
void print_event_loop_stats(event_loop_t *loop)
{
    event_loop_stats_t stats;
    
    if (!loop) return;
    
    get_event_loop_stats(loop, &stats);
    
    printf("Event Loop Statistics:\n");
    printf("  Total events: %lu\n", stats.total_events);
    printf("  Read events: %lu\n", stats.read_events);
    printf("  Write events: %lu\n", stats.write_events);
    printf("  Error events: %lu\n", stats.error_events);
    printf("  Packets batched: %lu\n", stats.packets_batched);
    printf("  Batches processed: %lu\n", stats.batches_processed);
    printf("  Zero-copy transfers: %lu\n", stats.zero_copy_transfers);
    printf("  Average batch size: %.2f\n", stats.avg_batch_size);
    printf("  Average loop time: %.2f us\n", stats.avg_loop_time_us);
}

/* Utility functions */
const char *event_type_to_string(event_type_t event_type)
{
    switch (event_type) {
        case EVENT_TYPE_READ: return "READ";
        case EVENT_TYPE_WRITE: return "WRITE";
        case EVENT_TYPE_ERROR: return "ERROR";
        case EVENT_TYPE_CLOSE: return "CLOSE";
        default: return "UNKNOWN";
    }
}

void log_event_loop_error(const char *function, const char *message)
{
    fprintf(stderr, "Event loop error in %s: %s\n", function, message);
    if (errno != 0) {
        perror("System error");
    }
}

/* Default event callbacks with zero-copy optimization */
int bridge_read_callback(event_loop_t *loop, int fd, event_type_t event_type, void *data)
{
    bridge_t *bridge = (bridge_t*)data;
    if (!bridge || !loop) {
        return -1;
    }
    
    /* Determine source and destination */
    nio_t *source_nio = NULL;
    nio_t *dest_nio = NULL;
    
    if (bridge->source_nio && bridge->source_nio->dptr && 
        *(int*)bridge->source_nio->dptr == fd) {
        source_nio = bridge->source_nio;
        dest_nio = bridge->destination_nio;
    } else if (bridge->destination_nio && bridge->destination_nio->dptr &&
               *(int*)bridge->destination_nio->dptr == fd) {
        source_nio = bridge->destination_nio;
        dest_nio = bridge->source_nio;
    } else {
        return -1; /* Unknown file descriptor */
    }
    
    if (!dest_nio || !dest_nio->dptr) {
        return -1;
    }
    
    int dest_fd = *(int*)dest_nio->dptr;
    
    /* Try zero-copy transfer if enabled and supported */
    if (loop->enable_zero_copy && can_use_zero_copy(fd, dest_fd)) {
        ssize_t transferred = zero_copy_transfer(fd, dest_fd, 65536);
        if (transferred > 0) {
            /* Update statistics */
            pthread_mutex_lock(&loop->stats_lock);
            loop->stats.zero_copy_transfers++;
            loop->stats.read_events++;
            pthread_mutex_unlock(&loop->stats_lock);
            
            /* Update NIO statistics */
            source_nio->packets_in++;
            source_nio->bytes_in += transferred;
            dest_nio->packets_out++;
            dest_nio->bytes_out += transferred;
            
            if (debug_level > 2) {
                printf("Zero-copy transfer: %zd bytes from %s to %s\n",
                       transferred, 
                       (source_nio == bridge->source_nio) ? "source" : "destination",
                       (dest_nio == bridge->destination_nio) ? "destination" : "source");
            }
            
            return 0;
        }
    }
    
    /* Fallback to traditional packet processing */
    return bridge_traditional_read(loop, bridge, source_nio, dest_nio);
}

int bridge_write_callback(event_loop_t *loop, int fd, event_type_t event_type, void *data)
{
    bridge_t *bridge = (bridge_t*)data;
    if (!bridge || !loop) {
        return -1;
    }
    
    /* Update write event statistics */
    pthread_mutex_lock(&loop->stats_lock);
    loop->stats.write_events++;
    pthread_mutex_unlock(&loop->stats_lock);
    
    /* For now, write events are primarily handled in read callbacks */
    /* This callback can be used for flow control and backpressure */
    
    if (debug_level > 2) {
        printf("Write event on fd %d for bridge %s\n", fd, bridge->name);
    }
    
    return 0;
}

int bridge_error_callback(event_loop_t *loop, int fd, event_type_t event_type, void *data)
{
    bridge_t *bridge = (bridge_t*)data;
    if (!bridge || !loop) {
        return -1;
    }
    
    /* Update error event statistics */
    pthread_mutex_lock(&loop->stats_lock);
    loop->stats.error_events++;
    pthread_mutex_unlock(&loop->stats_lock);
    
    fprintf(stderr, "Error event on fd %d for bridge %s\n", fd, bridge->name);
    
    /* Remove the problematic file descriptor from event loop */
    remove_event_handler(loop, fd);
    
    return -1;
}

/* Traditional packet processing fallback */
int bridge_traditional_read(event_loop_t *loop, bridge_t *bridge, nio_t *source_nio, nio_t *dest_nio)
{
    unsigned char *pkt = NULL;
    ssize_t bytes_received, bytes_sent;
    int is_pooled_buffer = 0;
    
    /* Get packet buffer */
    if (loop->buffer_pool) {
        pkt = (unsigned char *)get_buffer(loop->buffer_pool);
        is_pooled_buffer = (pkt != NULL);
    }
    
    if (!pkt) {
        /* Fallback to stack allocation */
        static unsigned char fallback_pkt[NIO_MAX_PKT_SIZE];
        pkt = fallback_pkt;
    }
    
    /* Receive packet */
    bytes_received = nio_recv(source_nio, pkt, NIO_MAX_PKT_SIZE);
    if (bytes_received <= 0) {
        if (is_pooled_buffer) {
            return_buffer(loop->buffer_pool, pkt);
        }
        if (bytes_received == 0) {
            return 0; /* No data available */
        }
        return -1; /* Error */
    }
    
    /* Apply packet filters if configured */
    int drop_packet = 0;
    if (bridge->filter_chain) {
        drop_packet = !process_filter_chain(bridge->filter_chain, pkt, bytes_received);
    }
    
    if (!drop_packet) {
        /* Send packet to destination */
        bytes_sent = nio_send(dest_nio, pkt, bytes_received);
        if (bytes_sent > 0) {
            /* Update statistics */
            source_nio->packets_in++;
            source_nio->bytes_in += bytes_received;
            dest_nio->packets_out++;
            dest_nio->bytes_out += bytes_sent;
            
            /* PCAP capture if enabled */
            if (bridge->capture) {
                pcap_capture_packet(bridge->capture, pkt, bytes_received);
            }
        }
    }
    
    /* Return buffer to pool */
    if (is_pooled_buffer) {
        return_buffer(loop->buffer_pool, pkt);
    }
    
    /* Update event loop statistics */
    pthread_mutex_lock(&loop->stats_lock);
    loop->stats.read_events++;
    if (!drop_packet && bytes_sent > 0) {
        loop->stats.packets_batched++;
    }
    pthread_mutex_unlock(&loop->stats_lock);
    
    return bytes_received;
}

/* Zero-copy operations implementation */
#ifdef __linux__

#include <sys/sendfile.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

/* Zero-copy transfer using splice() for compatible file descriptors */
int zero_copy_transfer(int in_fd, int out_fd, size_t count)
{
    if (in_fd < 0 || out_fd < 0 || count == 0) {
        return -1;
    }
    
    /* Create a pipe for splice operations */
    int pipe_fd[2];
    if (pipe(pipe_fd) == -1) {
        if (debug_level > 1) {
            perror("zero_copy_transfer: pipe creation failed");
        }
        return -1;
    }
    
    ssize_t bytes_transferred = 0;
    ssize_t total_transferred = 0;
    
    /* Splice from input to pipe, then from pipe to output */
    while (total_transferred < count) {
        size_t remaining = count - total_transferred;
        size_t chunk_size = (remaining > 65536) ? 65536 : remaining;
        
        /* Splice from input to pipe */
        bytes_transferred = splice(in_fd, NULL, pipe_fd[1], NULL, 
                                 chunk_size, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        
        if (bytes_transferred <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break; /* No more data available */
            }
            if (debug_level > 1) {
                perror("zero_copy_transfer: splice input failed");
            }
            break;
        }
        
        /* Splice from pipe to output */
        ssize_t bytes_out = splice(pipe_fd[0], NULL, out_fd, NULL,
                                 bytes_transferred, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        
        if (bytes_out <= 0) {
            if (debug_level > 1) {
                perror("zero_copy_transfer: splice output failed");
            }
            break;
        }
        
        total_transferred += bytes_out;
        
        if (bytes_out < bytes_transferred) {
            /* Partial write, adjust for next iteration */
            break;
        }
    }
    
    close(pipe_fd[0]);
    close(pipe_fd[1]);
    
    if (debug_level > 2) {
        printf("Zero-copy transfer: %zd bytes\n", total_transferred);
    }
    
    return total_transferred;
}

/* Setup memory-mapped packet socket for zero-copy receive */
int setup_packet_mmap(nio_t *nio)
{
    if (!nio || nio->type != NIO_TYPE_ETHERNET) {
        return -1;
    }
    
    int fd = *(int*)nio->dptr;
    if (fd < 0) {
        return -1;
    }
    
    /* Configure PACKET_MMAP ring buffer */
    struct tpacket_req req;
    memset(&req, 0, sizeof(req));
    
    /* Calculate ring buffer parameters */
    req.tp_block_size = getpagesize() * 4; /* 4 pages per block */
    req.tp_frame_size = 2048; /* Frame size for Ethernet */
    req.tp_block_nr = 64; /* Number of blocks */
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;
    
    /* Set up the ring buffer */
    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
        if (debug_level > 1) {
            perror("setup_packet_mmap: PACKET_RX_RING failed");
        }
        return -1;
    }
    
    /* Map the ring buffer into memory */
    size_t map_size = req.tp_block_size * req.tp_block_nr;
    void *ring_buffer = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                            MAP_SHARED, fd, 0);
    
    if (ring_buffer == MAP_FAILED) {
        if (debug_level > 1) {
            perror("setup_packet_mmap: mmap failed");
        }
        return -1;
    }
    
    /* Store mapping information in NIO structure */
    /* Note: This would require extending the nio_t structure to store mmap info */
    /* For now, we'll use a simple approach and store in a global table */
    
    if (debug_level > 0) {
        printf("PACKET_MMAP setup: %zu bytes mapped, %d frames\n", 
               map_size, req.tp_frame_nr);
    }
    
    return 0;
}

/* Enhanced zero-copy transfer with sendfile for file-to-socket operations */
int zero_copy_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    if (in_fd < 0 || out_fd < 0 || count == 0) {
        return -1;
    }
    
    ssize_t bytes_sent = sendfile(out_fd, in_fd, offset, count);
    
    if (bytes_sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; /* Would block, try again later */
        }
        if (debug_level > 1) {
            perror("zero_copy_sendfile failed");
        }
        return -1;
    }
    
    if (debug_level > 2) {
        printf("Zero-copy sendfile: %zd bytes\n", bytes_sent);
    }
    
    return bytes_sent;
}

/* Direct memory mapping for high-performance packet buffers */
int setup_zero_copy_buffers(event_loop_t *loop)
{
    if (!loop || !loop->enable_zero_copy) {
        return 0; /* Zero-copy disabled */
    }
    
    /* Allocate large contiguous memory region for zero-copy operations */
    size_t region_size = 16 * 1024 * 1024; /* 16MB region */
    
    void *zero_copy_region = mmap(NULL, region_size,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED,
                                 -1, 0);
    
    if (zero_copy_region == MAP_FAILED) {
        if (debug_level > 1) {
            perror("setup_zero_copy_buffers: mmap failed");
        }
        return -1;
    }
    
    /* Advise kernel about memory usage patterns */
    if (madvise(zero_copy_region, region_size, MADV_SEQUENTIAL) < 0) {
        if (debug_level > 1) {
            perror("setup_zero_copy_buffers: madvise failed");
        }
    }
    
    /* Store in event loop for later use */
    /* Note: This would require extending event_loop_t structure */
    
    if (debug_level > 0) {
        printf("Zero-copy buffer region setup: %zu bytes\n", region_size);
    }
    
    return 0;
}

/* Check if file descriptors support zero-copy operations */
int can_use_zero_copy(int fd1, int fd2)
{
    /* Check if file descriptors are suitable for splice operations */
    struct stat stat1, stat2;
    
    if (fstat(fd1, &stat1) < 0 || fstat(fd2, &stat2) < 0) {
        return 0;
    }
    
    /* splice() works best with pipes, sockets, and regular files */
    if (S_ISFIFO(stat1.st_mode) || S_ISSOCK(stat1.st_mode) || S_ISREG(stat1.st_mode)) {
        if (S_ISFIFO(stat2.st_mode) || S_ISSOCK(stat2.st_mode) || S_ISREG(stat2.st_mode)) {
            return 1;
        }
    }
    
    return 0;
}

#endif /* __linux__ */

/* CPU affinity and performance optimization functions */
int event_loop_configure_affinity(event_loop_t *loop)
{
    if (!loop || !cpu_affinity_is_available()) {
        return -1;
    }
    
    /* Get CPU topology for optimization */
    cpu_topology_t topology;
    if (get_cpu_topology(&topology) != 0) {
        return -1;
    }
    
    /* Configure affinity based on the number of bridges and CPU cores */
    int cpu_id = 0;
    
    /* Pin main event loop to a specific CPU */
    if (set_thread_affinity(pthread_self(), cpu_id) != 0) {
        if (debug_level > 0) {
            printf("Warning: Failed to set affinity for main event loop thread\n");
        }
        return -1;
    }
    
    if (debug_level > 0) {
        printf("Event loop pinned to CPU %d\n", cpu_id);
    }
    
    /* If we have worker threads (future extension), distribute them across cores */
    /* This is a placeholder for future multi-threaded event loop implementation */
    
    return 0;
}

int event_loop_optimize_numa(event_loop_t *loop)
{
    if (!loop) {
        return -1;
    }
    
#ifdef HAVE_NUMA
    /* Get CPU topology which includes NUMA information */
    cpu_topology_t topology;
    if (get_cpu_topology(&topology) != 0) {
        return -1;
    }
    
    /* Find the NUMA node of the current thread */
    int current_node = get_current_numa_node();
    if (current_node >= 0) {
        if (debug_level > 0) {
            printf("Event loop running on NUMA node %d\n", current_node);
        }
        
        /* Future: Could allocate buffers on the local NUMA node */
        /* This would require integration with buffer_pool.c */
    }
#else
    if (debug_level > 0) {
        printf("NUMA support not available\n");
    }
#endif
    
    return 0;
}
