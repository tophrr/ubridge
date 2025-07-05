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
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>

#ifdef __linux__
#include <sys/syscall.h>
/* Try to include NUMA support if available */
#ifdef HAVE_NUMA
#include <numa.h>
#endif
#endif

#include "buffer_pool.h"
#include "ubridge.h"

/* Internal helper functions */
static void *aligned_alloc_fallback(size_t alignment, size_t size);
static inline void *get_buffer_data(void *buffer_with_header);
static inline buffer_header_t *get_buffer_header(void *buffer_data);

/* Create a new buffer pool with default alignment */
buffer_pool_t *create_buffer_pool(size_t buffer_size, size_t buffer_count)
{
    return create_buffer_pool_aligned(buffer_size, buffer_count, CACHE_LINE_SIZE);
}

/* Create a new buffer pool with specified alignment */
buffer_pool_t *create_buffer_pool_aligned(size_t buffer_size, size_t buffer_count, size_t alignment)
{
    buffer_pool_t *pool;
    size_t total_buffer_size;
    size_t i;
    char *buffer_ptr;

    /* Validate parameters */
    if (buffer_size == 0 || buffer_count == 0 || buffer_count < MIN_BUFFER_COUNT || buffer_count > MAX_BUFFER_COUNT) {
        errno = EINVAL;
        return NULL;
    }

    /* Ensure alignment is power of 2 and at least pointer size */
    if (alignment == 0 || (alignment & (alignment - 1)) != 0 || alignment < sizeof(void*)) {
        alignment = CACHE_LINE_SIZE;
    }

    /* Allocate pool structure */
    if (posix_memalign((void**)&pool, CACHE_LINE_SIZE, sizeof(buffer_pool_t)) != 0) {
        return NULL;
    }
    memset(pool, 0, sizeof(buffer_pool_t));

    /* Initialize pool configuration */
    pool->buffer_size = buffer_size;
    pool->buffer_count = buffer_count;
    pool->alignment = alignment;
    pool->allow_fallback = 1;

    /* Calculate total size needed for all buffers including headers */
    total_buffer_size = ALIGN_TO_CACHE_LINE(sizeof(buffer_header_t) + buffer_size);
    pool->memory_region_size = total_buffer_size * buffer_count;

    /* Allocate memory region for all buffers */
    if (posix_memalign(&pool->memory_region, alignment, pool->memory_region_size) != 0) {
        free(pool);
        return NULL;
    }
    memset(pool->memory_region, 0, pool->memory_region_size);

    /* Allocate array for free buffer pointers */
    pool->free_buffers = malloc(buffer_count * sizeof(void*));
    if (!pool->free_buffers) {
        free(pool->memory_region);
        free(pool);
        return NULL;
    }

    /* Initialize all buffers and add them to free list */
    buffer_ptr = (char*)pool->memory_region;
    for (i = 0; i < buffer_count; i++) {
        buffer_header_t *header = (buffer_header_t*)buffer_ptr;
        
        /* Initialize buffer header */
        header->pool = pool;
        header->magic = BUFFER_MAGIC;
        header->size = buffer_size;
        
        /* Add to free list */
        pool->free_buffers[i] = get_buffer_data(header);
        
        buffer_ptr += total_buffer_size;
    }

    /* Initialize atomic counters */
    atomic_store(&pool->free_count, buffer_count);
    atomic_store(&pool->head_index, 0);
    atomic_store(&pool->stats.current_allocated, 0);
    atomic_store(&pool->stats.peak_allocated, 0);

    return pool;
}

/* Destroy buffer pool and free all memory */
void destroy_buffer_pool(buffer_pool_t *pool)
{
    if (!pool) return;

    if (pool->memory_region) {
        free(pool->memory_region);
    }
    if (pool->free_buffers) {
        free(pool->free_buffers);
    }
    free(pool);
}

/* Get a buffer from the pool (lock-free) */
void *get_buffer(buffer_pool_t *pool)
{
    uint32_t current_free, head_idx;
    uint_fast32_t expected_free, expected_head;
    void *buffer;

    if (unlikely(!pool)) {
        errno = EINVAL;
        return NULL;
    }

    /* Try to get buffer from pool using lock-free algorithm */
    do {
        current_free = atomic_load(&pool->free_count);
        if (current_free == 0) {
            /* Pool exhausted - try fallback allocation if allowed */
            if (pool->allow_fallback) {
                buffer = aligned_alloc_fallback(pool->alignment, 
                                              sizeof(buffer_header_t) + pool->buffer_size);
                if (buffer) {
                    buffer_header_t *header = (buffer_header_t*)buffer;
                    header->pool = NULL; /* Mark as fallback allocation */
                    header->magic = BUFFER_MAGIC;
                    header->size = pool->buffer_size;
                    
                    atomic_fetch_add(&pool->stats.alloc_failures, 1);
                    atomic_fetch_add(&pool->stats.cache_misses, 1);
                    return get_buffer_data(header);
                }
            }
            atomic_fetch_add(&pool->stats.alloc_failures, 1);
            errno = ENOMEM;
            return NULL;
        }
        
        head_idx = atomic_load(&pool->head_index);
        buffer = pool->free_buffers[head_idx % pool->buffer_count];
        
        expected_free = current_free;
        expected_head = head_idx;
        
    } while (!atomic_compare_exchange_weak(&pool->free_count, &expected_free, expected_free - 1) ||
             !atomic_compare_exchange_weak(&pool->head_index, &expected_head, expected_head + 1));

    /* Update statistics */
    atomic_fetch_add(&pool->stats.buffers_allocated, 1);
    atomic_fetch_add(&pool->stats.cache_hits, 1);
    
    uint32_t current_alloc = atomic_fetch_add(&pool->stats.current_allocated, 1) + 1;
    uint_fast32_t peak = atomic_load(&pool->stats.peak_allocated);
    while (current_alloc > peak) {
        uint_fast32_t expected_peak = peak;
        if (atomic_compare_exchange_weak(&pool->stats.peak_allocated, &expected_peak, current_alloc)) {
            break;
        }
        peak = expected_peak;
    }

    return buffer;
}

/* Return a buffer to the pool */
void return_buffer(buffer_pool_t *pool, void *buffer)
{
    buffer_header_t *header;
    uint32_t current_free, tail_idx;
    uint_fast32_t expected_free;

    if (unlikely(!buffer)) {
        return;
    }

    header = get_buffer_header(buffer);
    
    /* Validate buffer */
    if (unlikely(header->magic != BUFFER_MAGIC)) {
        fprintf(stderr, "return_buffer: Invalid buffer magic\n");
        return;
    }

    /* Handle fallback allocation */
    if (header->pool == NULL) {
        free(header);
        return;
    }

    if (unlikely(header->pool != pool)) {
        fprintf(stderr, "return_buffer: Buffer belongs to different pool\n");
        return;
    }

    /* Add buffer back to free list using lock-free algorithm */
    do {
        current_free = atomic_load(&pool->free_count);
        if (current_free >= pool->buffer_count) {
            fprintf(stderr, "return_buffer: Pool overflow\n");
            return;
        }
        
        tail_idx = (atomic_load(&pool->head_index) + current_free) % pool->buffer_count;
        pool->free_buffers[tail_idx] = buffer;
        
        expected_free = current_free;
        
    } while (!atomic_compare_exchange_weak(&pool->free_count, &expected_free, expected_free + 1));

    /* Update statistics */
    atomic_fetch_add(&pool->stats.buffers_freed, 1);
    atomic_fetch_sub(&pool->stats.current_allocated, 1);
}

/* Get buffer with timeout (milliseconds) */
void *get_buffer_timeout(buffer_pool_t *pool, int timeout_ms)
{
    struct timespec start, current;
    void *buffer;
    long elapsed_ms;

    if (timeout_ms <= 0) {
        return get_buffer(pool);
    }

    clock_gettime(CLOCK_MONOTONIC, &start);

    do {
        buffer = get_buffer(pool);
        if (buffer) {
            return buffer;
        }

        /* Small delay before retry */
        usleep(100); /* 100 microseconds */

        clock_gettime(CLOCK_MONOTONIC, &current);
        elapsed_ms = (current.tv_sec - start.tv_sec) * 1000 + 
                     (current.tv_nsec - start.tv_nsec) / 1000000;
                     
    } while (elapsed_ms < timeout_ms);

    return NULL; /* Timeout */
}

/* Get buffer pool statistics */
void get_buffer_pool_stats(buffer_pool_t *pool, buffer_pool_stats_t *stats)
{
    if (!pool || !stats) {
        return;
    }

    stats->buffers_allocated = atomic_load(&pool->stats.buffers_allocated);
    stats->buffers_freed = atomic_load(&pool->stats.buffers_freed);
    stats->alloc_failures = atomic_load(&pool->stats.alloc_failures);
    stats->cache_hits = atomic_load(&pool->stats.cache_hits);
    stats->cache_misses = atomic_load(&pool->stats.cache_misses);
    stats->current_allocated = atomic_load(&pool->stats.current_allocated);
    stats->peak_allocated = atomic_load(&pool->stats.peak_allocated);
}

/* Reset buffer pool statistics */
void reset_buffer_pool_stats(buffer_pool_t *pool)
{
    if (!pool) return;

    atomic_store(&pool->stats.buffers_allocated, 0);
    atomic_store(&pool->stats.buffers_freed, 0);
    atomic_store(&pool->stats.alloc_failures, 0);
    atomic_store(&pool->stats.cache_hits, 0);
    atomic_store(&pool->stats.cache_misses, 0);
    atomic_store(&pool->stats.peak_allocated, atomic_load(&pool->stats.current_allocated));
}

/* Get buffer pool utilization (0.0 to 1.0) */
double get_buffer_pool_utilization(buffer_pool_t *pool)
{
    if (!pool) return 0.0;

    uint32_t allocated = atomic_load(&pool->stats.current_allocated);
    return (double)allocated / (double)pool->buffer_count;
}

/* Get optimal buffer count based on expected concurrent operations */
size_t get_optimal_buffer_count(size_t expected_concurrent_operations)
{
    size_t optimal = expected_concurrent_operations * 2; /* 2x for safety margin */
    
    if (optimal < MIN_BUFFER_COUNT) {
        optimal = MIN_BUFFER_COUNT;
    } else if (optimal > MAX_BUFFER_COUNT) {
        optimal = MAX_BUFFER_COUNT;
    }
    
    return optimal;
}

/* Get system cache line size */
size_t get_system_cache_line_size(void)
{
    long cache_line_size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    return (cache_line_size > 0) ? cache_line_size : CACHE_LINE_SIZE;
}

/* Helper function: aligned allocation fallback */
static void *aligned_alloc_fallback(size_t alignment, size_t size)
{
    void *ptr;
    if (posix_memalign(&ptr, alignment, size) == 0) {
        return ptr;
    }
    return malloc(size); /* Fallback to regular malloc */
}

/* Helper function: get buffer data pointer from header */
static inline void *get_buffer_data(void *buffer_with_header)
{
    return (char*)buffer_with_header + sizeof(buffer_header_t);
}

/* Helper function: get buffer header from data pointer */
static inline buffer_header_t *get_buffer_header(void *buffer_data)
{
    return (buffer_header_t*)((char*)buffer_data - sizeof(buffer_header_t));
}

#if defined(__linux__) && defined(HAVE_NUMA)
/* NUMA-aware buffer pool creation */
buffer_pool_t *create_buffer_pool_numa(size_t buffer_size, size_t buffer_count, int numa_node)
{
    buffer_pool_t *pool;
    
    /* Check if NUMA is available */
    if (numa_available() < 0) {
        return create_buffer_pool(buffer_size, buffer_count);
    }

    /* Bind to NUMA node for allocation */
    struct bitmask *old_mask = numa_get_membind();
    struct bitmask *new_mask = numa_allocate_nodemask();
    numa_bitmask_setbit(new_mask, numa_node);
    numa_set_membind(new_mask);

    /* Create pool */
    pool = create_buffer_pool(buffer_size, buffer_count);

    /* Restore original NUMA binding */
    numa_set_membind(old_mask);
    numa_free_nodemask(new_mask);
    numa_free_nodemask(old_mask);

    return pool;
}
#endif

/* Global buffer pool management for application-wide packet processing */

/**
 * Initialize global buffer pool with optimal settings
 * Called once at application startup
 */
int init_global_buffer_pool(void)
{
    size_t buffer_count;
    
    if (global_packet_pool != NULL) {
        /* Already initialized */
        return 0;
    }
    
    /* Determine optimal buffer count based on system */
    buffer_count = get_optimal_buffer_count(64); /* Assume ~64 concurrent operations */
    
    /* Create buffer pool with standard packet size */
    global_packet_pool = create_buffer_pool(DEFAULT_BUFFER_SIZE, buffer_count);
    if (global_packet_pool == NULL) {
        fprintf(stderr, "Failed to create global packet buffer pool\n");
        return -1;
    }
    
    /* Enable fallback allocation for high-load scenarios */
    global_packet_pool->allow_fallback = 1;
    
    if (debug_level > 0) {
        printf("Initialized global buffer pool: %zu buffers of %zu bytes each\n", 
               buffer_count, (size_t)DEFAULT_BUFFER_SIZE);
    }
    
    return 0;
}

/**
 * Cleanup global buffer pool
 * Called at application shutdown
 */
void cleanup_global_buffer_pool(void)
{
    if (global_packet_pool != NULL) {
        buffer_pool_stats_t stats;
        get_buffer_pool_stats(global_packet_pool, &stats);
        
        if (debug_level > 0) {
            printf("Buffer pool statistics:\n");
            printf("  Buffers allocated: %lu\n", stats.buffers_allocated);
            printf("  Buffers freed: %lu\n", stats.buffers_freed);
            printf("  Allocation failures: %lu\n", stats.alloc_failures);
            printf("  Cache hits: %lu\n", stats.cache_hits);
            printf("  Cache misses: %lu\n", stats.cache_misses);
            printf("  Peak allocated: %lu\n", (unsigned long)stats.peak_allocated);
        }
        
        destroy_buffer_pool(global_packet_pool);
        global_packet_pool = NULL;
    }
}
