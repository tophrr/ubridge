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
#include <sys/socket.h>

#ifdef __linux__
#include <sys/sendfile.h>
#endif

#include "event_loop.h"
#include "ubridge.h"
#include "nio.h"
#include "packet_filter.h"

/* Create packet batch */
packet_batch_t *create_packet_batch(int capacity)
{
    packet_batch_t *batch;
    
    if (capacity <= 0 || capacity > MAX_BATCH_SIZE) {
        capacity = DEFAULT_BATCH_SIZE;
    }
    
    batch = malloc(sizeof(packet_batch_t));
    if (!batch) {
        log_event_loop_error("create_packet_batch", "Failed to allocate batch");
        return NULL;
    }
    
    memset(batch, 0, sizeof(packet_batch_t));
    batch->capacity = capacity;
    
    /* Allocate arrays */
    batch->buffers = malloc(sizeof(void*) * capacity);
    batch->lengths = malloc(sizeof(size_t) * capacity);
    batch->addrs = malloc(sizeof(struct sockaddr_storage) * capacity);
    batch->addr_lens = malloc(sizeof(socklen_t) * capacity);
    
    if (!batch->buffers || !batch->lengths || !batch->addrs || !batch->addr_lens) {
        destroy_packet_batch(batch);
        log_event_loop_error("create_packet_batch", "Failed to allocate batch arrays");
        return NULL;
    }
    
    if (debug_level > 1) {
        printf("Created packet batch with capacity %d\n", capacity);
    }
    
    return batch;
}

/* Destroy packet batch */
void destroy_packet_batch(packet_batch_t *batch)
{
    if (!batch) return;
    
    /* Return any remaining buffers to pool */
    for (int i = 0; i < batch->count; i++) {
        if (batch->buffers[i]) {
            return_buffer(global_packet_pool, batch->buffers[i]);
        }
    }
    
    if (batch->buffers) free(batch->buffers);
    if (batch->lengths) free(batch->lengths);
    if (batch->addrs) free(batch->addrs);
    if (batch->addr_lens) free(batch->addr_lens);
    
    free(batch);
    
    if (debug_level > 1) {
        printf("Destroyed packet batch\n");
    }
}

/* Add packet to batch */
int add_packet_to_batch(packet_batch_t *batch, void *buffer, size_t length, 
                       struct sockaddr *addr, socklen_t addr_len)
{
    if (!batch || !buffer || batch->count >= batch->capacity) {
        return -1;
    }
    
    batch->buffers[batch->count] = buffer;
    batch->lengths[batch->count] = length;
    
    if (addr && addr_len <= sizeof(struct sockaddr_storage)) {
        memcpy(&batch->addrs[batch->count], addr, addr_len);
        batch->addr_lens[batch->count] = addr_len;
    } else {
        batch->addr_lens[batch->count] = 0;
    }
    
    batch->count++;
    
    return 0;
}

/* Process packet batch */
int process_packet_batch(event_loop_t *loop, packet_batch_t *batch)
{
    int processed = 0;
    int dropped = 0;
    
    if (!loop || !batch || batch->count == 0) {
        return 0;
    }
    
    /* Process each packet in the batch */
    for (int i = 0; i < batch->count; i++) {
        void *pkt = batch->buffers[i];
        size_t pkt_len = batch->lengths[i];
        bridge_t *bridge = batch->bridge;
        
        if (!pkt || !bridge) {
            continue;
        }
        
        /* Update bridge statistics */
        bridge->packets_processed++;
        bridge->bytes_processed += pkt_len;
        
        /* Process filters if configured */
        int drop_packet = 0;
        if (bridge->filter_chain && bridge->filter_chain->enabled_count > 0) {
            int filter_result = process_filter_chain(bridge->filter_chain, pkt, pkt_len);
            if (filter_result == FILTER_ACTION_DROP) {
                drop_packet = 1;
                bridge->packets_dropped++;
                dropped++;
                
                if (debug_level > 1) {
                    printf("Packet %d in batch dropped by filter chain\n", i);
                }
            }
        } else if (bridge->packet_filters != NULL) {
            /* Fallback to legacy filters */
            packet_filter_t *filter = bridge->packet_filters;
            while (filter != NULL) {
                if (filter->handler(pkt, pkt_len, filter->data) == FILTER_ACTION_DROP) {
                    drop_packet = 1;
                    bridge->packets_dropped++;
                    dropped++;
                    break;
                }
                filter = filter->next;
            }
        }
        
        if (drop_packet) {
            /* Return buffer to pool */
            return_buffer(loop->buffer_pool, pkt);
            continue;
        }
        
        /* Send packet to destination */
        if (batch->destination_nio) {
            ssize_t bytes_sent = nio_send(batch->destination_nio, pkt, pkt_len);
            if (bytes_sent >= 0) {
                batch->destination_nio->packets_out++;
                batch->destination_nio->bytes_out += bytes_sent;
                processed++;
            } else {
                if (debug_level > 0) {
                    printf("Failed to send packet %d in batch: %s\n", i, strerror(errno));
                }
            }
        }
        
        /* Return buffer to pool */
        return_buffer(loop->buffer_pool, pkt);
    }
    
    /* Update event loop statistics */
    pthread_mutex_lock(&loop->stats_lock);
    loop->stats.packets_batched += batch->count;
    loop->stats.batches_processed++;
    
    if (loop->stats.batches_processed > 0) {
        loop->stats.avg_batch_size = (double)loop->stats.packets_batched / 
                                   (double)loop->stats.batches_processed;
    }
    pthread_mutex_unlock(&loop->stats_lock);
    
    if (debug_level > 1) {
        printf("Processed batch: %d packets, %d processed, %d dropped\n", 
               batch->count, processed, dropped);
    }
    
    return processed;
}

/* Clear packet batch */
void clear_packet_batch(packet_batch_t *batch)
{
    if (!batch) return;
    
    /* Return any buffers to pool */
    for (int i = 0; i < batch->count; i++) {
        if (batch->buffers[i]) {
            return_buffer(global_packet_pool, batch->buffers[i]);
            batch->buffers[i] = NULL;
        }
    }
    
    batch->count = 0;
    
    if (debug_level > 2) {
        printf("Cleared packet batch: capacity=%d\n", batch->capacity);
    }
}
