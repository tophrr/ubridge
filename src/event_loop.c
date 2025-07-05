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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <linux/if_packet.h>
#endif

#ifdef __FreeBSD__
#include <sys/event.h>
#endif

#include "event_loop.h"
#include "ubridge.h"
#include "nio.h"
#include "packet_filter.h"

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
