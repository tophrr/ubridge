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

#ifndef BUFFER_POOL_H_
#define BUFFER_POOL_H_

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>

/* Cache line size for alignment (typically 64 bytes on modern CPUs) */
#define CACHE_LINE_SIZE 64
#define ALIGN_TO_CACHE_LINE(x) (((x) + CACHE_LINE_SIZE - 1) & ~(CACHE_LINE_SIZE - 1))

/* Default buffer pool configuration - optimized for performance */
#define DEFAULT_BUFFER_SIZE     65536   /* 64KB packets */
#define DEFAULT_BUFFER_COUNT    2048    /* Optimal number of buffers for most workloads */
#define MIN_BUFFER_COUNT        64      /* Minimum buffers */
#define MAX_BUFFER_COUNT        16384   /* Maximum buffers */

/* Buffer pool statistics */
typedef struct buffer_pool_stats {
    uint64_t buffers_allocated;
    uint64_t buffers_freed;
    uint64_t alloc_failures;
    uint64_t cache_hits;
    uint64_t cache_misses;
    atomic_uint_fast32_t current_allocated;
    atomic_uint_fast32_t peak_allocated;
} buffer_pool_stats_t;

/* Lock-free buffer pool structure */
typedef struct buffer_pool {
    /* Pool configuration */
    size_t buffer_size;
    size_t buffer_count;
    size_t alignment;
    
    /* Memory region management */
    void *memory_region;
    size_t memory_region_size;
    
    /* Lock-free stack for available buffers */
    void **free_buffers;
    atomic_uint_fast32_t free_count;
    atomic_uint_fast32_t head_index;
    
    /* Statistics */
    buffer_pool_stats_t stats;
    
    /* Fallback allocation for when pool is exhausted */
    int allow_fallback;
    
    /* Cache line aligned to prevent false sharing */
} __attribute__((aligned(CACHE_LINE_SIZE))) buffer_pool_t;

/* Buffer header for tracking */
typedef struct buffer_header {
    buffer_pool_t *pool;
    uint32_t magic;
    uint32_t size;
} __attribute__((packed)) buffer_header_t;

#define BUFFER_MAGIC 0xDEADBEEF

/* Buffer pool API */
buffer_pool_t *create_buffer_pool(size_t buffer_size, size_t buffer_count);
buffer_pool_t *create_buffer_pool_aligned(size_t buffer_size, size_t buffer_count, size_t alignment);
void destroy_buffer_pool(buffer_pool_t *pool);

/* Buffer allocation/deallocation */
void *get_buffer(buffer_pool_t *pool);
void return_buffer(buffer_pool_t *pool, void *buffer);
void *get_buffer_timeout(buffer_pool_t *pool, int timeout_ms);

/* Buffer pool management */
int resize_buffer_pool(buffer_pool_t *pool, size_t new_count);
void clear_buffer_pool(buffer_pool_t *pool);

/* Statistics and monitoring */
void get_buffer_pool_stats(buffer_pool_t *pool, buffer_pool_stats_t *stats);
void reset_buffer_pool_stats(buffer_pool_t *pool);
double get_buffer_pool_utilization(buffer_pool_t *pool);

/* Utility functions */
size_t get_optimal_buffer_count(size_t expected_concurrent_operations);
size_t get_system_cache_line_size(void);

/* NUMA-aware allocation (Linux only) */
#if defined(__linux__) && defined(HAVE_NUMA)
buffer_pool_t *create_buffer_pool_numa(size_t buffer_size, size_t buffer_count, int numa_node);
#endif

#endif /* !BUFFER_POOL_H_ */
