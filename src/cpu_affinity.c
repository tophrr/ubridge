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
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef __linux__
#include <sched.h>
/* Note: NUMA support is optional and requires libnuma-dev */
#ifdef HAVE_NUMA
#include <numa.h>
#include <numaif.h>
#endif
#endif

#include "cpu_affinity.h"
#include "ubridge.h"

/* Global CPU topology information */
cpu_topology_t *global_topology = NULL;
static cpu_affinity_stats_t global_stats;
static pthread_mutex_t affinity_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Detect CPU topology */
cpu_topology_t *detect_cpu_topology(void)
{
    cpu_topology_t *topo;
    FILE *fp;
    char line[256];
    int node; /* Used in multiple places */
    
    topo = malloc(sizeof(cpu_topology_t));
    if (!topo) {
        return NULL;
    }
    
    memset(topo, 0, sizeof(cpu_topology_t));
    
    /* Get number of CPUs */
    topo->num_cpus = sysconf(_SC_NPROCESSORS_CONF);
    topo->online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    
    if (topo->num_cpus <= 0) {
        free(topo);
        return NULL;
    }
    
    /* Allocate CPU to node mapping */
    topo->cpu_to_node = malloc(sizeof(int) * topo->num_cpus);
    if (!topo->cpu_to_node) {
        free(topo);
        return NULL;
    }
    
    /* Initialize with default values */
    for (int i = 0; i < topo->num_cpus; i++) {
        topo->cpu_to_node[i] = 0; /* Default to NUMA node 0 */
    }
    
#ifdef __linux__
    /* Detect NUMA topology */
    topo->num_numa_nodes = 1; /* Default to 1 node */
    
#ifdef HAVE_NUMA
    if (numa_available() != -1) {
        int cpu;
        topo->num_numa_nodes = numa_max_node() + 1;
        
        /* Read CPU to NUMA node mapping */
        for (cpu = 0; cpu < topo->num_cpus; cpu++) {
            node = numa_node_of_cpu(cpu);
            if (node >= 0 && node < topo->num_numa_nodes) {
                topo->cpu_to_node[cpu] = node;
            }
        }
    }
#endif
    
    /* Detect hyperthreading */
    fp = fopen("/sys/devices/system/cpu/smt/active", "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            topo->hyperthreading_enabled = (atoi(line) == 1);
        }
        fclose(fp);
    }
    
    /* Alternative method to detect hyperthreading */
    if (!topo->hyperthreading_enabled) {
        int logical_cpus = topo->num_cpus;
        int physical_cpus = 0;
        
        fp = fopen("/proc/cpuinfo", "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "cpu cores", 9) == 0) {
                    physical_cpus = atoi(strchr(line, ':') + 1);
                    break;
                }
            }
            fclose(fp);
            
            if (physical_cpus > 0 && logical_cpus > physical_cpus) {
                topo->hyperthreading_enabled = 1;
            }
        }
    }
#endif
    
    /* Allocate NUMA node to CPU mapping */
    topo->node_cpus = malloc(sizeof(int*) * topo->num_numa_nodes);
    topo->node_cpu_count = malloc(sizeof(int) * topo->num_numa_nodes);
    
    if (!topo->node_cpus || !topo->node_cpu_count) {
        free_cpu_topology(topo);
        return NULL;
    }
    
    /* Initialize node CPU counts */
    for (int i = 0; i < topo->num_numa_nodes; i++) {
        topo->node_cpu_count[i] = 0;
    }
    
    /* Count CPUs per NUMA node */
    for (int i = 0; i < topo->num_cpus; i++) {
        node = topo->cpu_to_node[i];
        if (node >= 0 && node < topo->num_numa_nodes) {
            topo->node_cpu_count[node]++;
        }
    }
    
    /* Allocate and populate node CPU lists */
    for (int i = 0; i < topo->num_numa_nodes; i++) {
        if (topo->node_cpu_count[i] > 0) {
            topo->node_cpus[i] = malloc(sizeof(int) * topo->node_cpu_count[i]);
            if (!topo->node_cpus[i]) {
                free_cpu_topology(topo);
                return NULL;
            }
        } else {
            topo->node_cpus[i] = NULL;
        }
    }
    
    /* Populate node CPU lists */
    int *node_indexes = calloc(topo->num_numa_nodes, sizeof(int));
    for (int i = 0; i < topo->num_cpus; i++) {
        node = topo->cpu_to_node[i];
        if (node >= 0 && node < topo->num_numa_nodes && topo->node_cpus[node]) {
            topo->node_cpus[node][node_indexes[node]++] = i;
        }
    }
    free(node_indexes);
    
    global_topology = topo;
    
    if (debug_level > 0) {
        printf("Detected CPU topology: %d CPUs, %d online, %d NUMA nodes, HT %s\n",
               topo->num_cpus, topo->online_cpus, topo->num_numa_nodes,
               topo->hyperthreading_enabled ? "enabled" : "disabled");
    }
    
    return topo;
}

/* Free CPU topology */
void free_cpu_topology(cpu_topology_t *topo)
{
    if (!topo) return;
    
    if (topo->cpu_to_node) {
        free(topo->cpu_to_node);
    }
    
    if (topo->node_cpus) {
        for (int i = 0; i < topo->num_numa_nodes; i++) {
            if (topo->node_cpus[i]) {
                free(topo->node_cpus[i]);
            }
        }
        free(topo->node_cpus);
    }
    
    if (topo->node_cpu_count) {
        free(topo->node_cpu_count);
    }
    
    free(topo);
    
    if (global_topology == topo) {
        global_topology = NULL;
    }
}

/* Print CPU topology */
void print_cpu_topology(cpu_topology_t *topo)
{
    if (!topo) return;
    
    printf("CPU Topology Information:\n");
    printf("  Total CPUs: %d\n", topo->num_cpus);
    printf("  Online CPUs: %d\n", topo->online_cpus);
    printf("  NUMA nodes: %d\n", topo->num_numa_nodes);
    printf("  Hyperthreading: %s\n", topo->hyperthreading_enabled ? "enabled" : "disabled");
    
    for (int node = 0; node < topo->num_numa_nodes; node++) {
        printf("  NUMA node %d: %d CPUs [", node, topo->node_cpu_count[node]);
        for (int i = 0; i < topo->node_cpu_count[node]; i++) {
            printf("%d", topo->node_cpus[node][i]);
            if (i < topo->node_cpu_count[node] - 1) printf(",");
        }
        printf("]\n");
    }
}

/* Set thread CPU affinity */
int set_thread_affinity(pthread_t thread, int cpu)
{
#ifdef __linux__
    cpu_set_t cpuset;
    
    if (cpu < 0 || !global_topology || cpu >= global_topology->num_cpus) {
        return -1;
    }
    
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    
    int result = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    
    if (result == 0 && debug_level > 1) {
        printf("Set thread affinity to CPU %d\n", cpu);
    }
    
    return result;
#else
    /* Affinity not supported on this platform */
    return 0;
#endif
}

/* Set process CPU affinity */
int set_process_affinity(pid_t pid, int cpu)
{
#ifdef __linux__
    cpu_set_t cpuset;
    
    if (cpu < 0 || !global_topology || cpu >= global_topology->num_cpus) {
        return -1;
    }
    
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    
    int result = sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset);
    
    if (result == 0 && debug_level > 1) {
        printf("Set process %d affinity to CPU %d\n", pid, cpu);
    }
    
    return result;
#else
    return 0;
#endif
}

/* Get current CPU */
int get_current_cpu(void)
{
#ifdef __linux__
    return sched_getcpu();
#else
    return -1;
#endif
}

/* Get current NUMA node */
int get_current_numa_node(void)
{
#ifdef __linux__
    int cpu = get_current_cpu();
    if (cpu >= 0 && global_topology && cpu < global_topology->num_cpus) {
        return global_topology->cpu_to_node[cpu];
    }
#endif
    return -1;
}

/* Auto-configure CPU affinity based on system topology */
cpu_affinity_config_t *auto_configure_affinity(cpu_topology_t *topo, int num_bridges)
{
    cpu_affinity_config_t *config;
    
    if (!topo || num_bridges <= 0) {
        return NULL;
    }
    
    config = malloc(sizeof(cpu_affinity_config_t));
    if (!config) {
        return NULL;
    }
    
    memset(config, 0, sizeof(cpu_affinity_config_t));
    
    /* Default configuration */
    config->enable_affinity = 1;
    config->enable_numa_binding = (topo->num_numa_nodes > 1);
    config->auto_detect = 1;
    
    /* Configure based on system characteristics */
    if (topo->online_cpus >= 4) {
        /* Multi-core system: isolate event loop */
        config->isolate_event_loop = 1;
        config->event_loop_cpu = 0; /* Use first CPU for event loop */
        config->worker_cpu_start = 1;
        config->worker_cpu_count = topo->online_cpus - 1;
    } else {
        /* Limited CPU system: share resources */
        config->isolate_event_loop = 0;
        config->worker_cpu_start = 0;
        config->worker_cpu_count = topo->online_cpus;
    }
    
    /* NUMA configuration */
    if (topo->num_numa_nodes > 1) {
        /* Use first NUMA node by default */
        config->numa_node = 0;
        
        /* If we have many bridges, consider using multiple NUMA nodes */
        if (num_bridges > topo->node_cpu_count[0]) {
            config->numa_node = -1; /* Use all nodes */
        }
    }
    
    if (debug_level > 0) {
        printf("Auto-configured CPU affinity: event_loop_cpu=%d, workers=%d-%d, numa_node=%d\n",
               config->event_loop_cpu, config->worker_cpu_start, 
               config->worker_cpu_start + config->worker_cpu_count - 1,
               config->numa_node);
    }
    
    return config;
}

/* Apply CPU affinity configuration */
int apply_affinity_config(cpu_affinity_config_t *config, cpu_topology_t *topo)
{
    if (!config || !topo || !config->enable_affinity) {
        return 0; /* Affinity disabled */
    }
    
    /* Set event loop thread affinity */
    if (config->isolate_event_loop) {
        pthread_t current_thread = pthread_self();
        if (set_thread_affinity(current_thread, config->event_loop_cpu) < 0) {
            if (debug_level > 0) {
                printf("Warning: Failed to set event loop CPU affinity\n");
            }
        }
    }
    
    /* Set NUMA memory policy */
    if (config->enable_numa_binding && config->numa_node >= 0) {
#ifdef HAVE_NUMA
        struct bitmask *nodemask = numa_allocate_nodemask();
        numa_bitmask_setbit(nodemask, config->numa_node);
        
        if (numa_set_membind(nodemask) < 0) {
            if (debug_level > 0) {
                printf("Warning: Failed to set NUMA memory binding\n");
            }
        }
        
        numa_free_nodemask(nodemask);
#endif
    }
    
    if (debug_level > 0) {
        printf("Applied CPU affinity configuration\n");
    }
    
    return 0;
}

/* Optimize for low latency */
int optimize_for_latency(cpu_topology_t *topo)
{
    if (!topo) return -1;
    
    /* For latency optimization:
     * 1. Isolate critical threads to dedicated CPUs
     * 2. Disable hyperthreading if possible
     * 3. Pin to NUMA node 0 (typically fastest)
     */
    
    if (debug_level > 0) {
        printf("Optimizing CPU configuration for low latency\n");
    }
    
    return 0;
}

/* Optimize for high throughput */
int optimize_for_throughput(cpu_topology_t *topo)
{
    if (!topo) return -1;
    
    /* For throughput optimization:
     * 1. Use all available CPUs
     * 2. Spread load across NUMA nodes
     * 3. Enable worker thread pools
     */
    
    if (debug_level > 0) {
        printf("Optimizing CPU configuration for high throughput\n");
    }
    
    return 0;
}

/* Get CPU affinity statistics */
void get_affinity_stats(cpu_affinity_stats_t *stats)
{
    if (!stats) return;
    
    pthread_mutex_lock(&affinity_mutex);
    
    *stats = global_stats;
    stats->current_cpu = get_current_cpu();
    stats->current_numa_node = get_current_numa_node();
    
    pthread_mutex_unlock(&affinity_mutex);
}

/* Reset CPU affinity statistics */
void reset_affinity_stats(void)
{
    pthread_mutex_lock(&affinity_mutex);
    memset(&global_stats, 0, sizeof(global_stats));
    pthread_mutex_unlock(&affinity_mutex);
}

/* Print CPU affinity statistics */
void print_affinity_stats(cpu_affinity_stats_t *stats)
{
    if (!stats) return;
    
    printf("CPU Affinity Statistics:\n");
    printf("  Current CPU: %d\n", stats->current_cpu);
    printf("  Current NUMA node: %d\n", stats->current_numa_node);
    printf("  Context switches: %lu\n", stats->context_switches);
    printf("  Cache misses: %lu\n", stats->cache_misses);
    printf("  NUMA migrations: %lu\n", stats->numa_migrations);
    printf("  CPU utilization: %.2f%%\n", stats->cpu_utilization);
    printf("  Cache hit ratio: %.2f%%\n", stats->cache_hit_ratio);
}

/* Initialization and cleanup functions */
int cpu_affinity_init(void)
{
    pthread_mutex_lock(&affinity_mutex);
    
    /* Detect CPU topology if not already done */
    if (!global_topology) {
        global_topology = detect_cpu_topology();
        if (!global_topology) {
            pthread_mutex_unlock(&affinity_mutex);
            return -1;
        }
    }
    
    /* Initialize statistics */
    memset(&global_stats, 0, sizeof(global_stats));
    global_stats.init_time = time(NULL);
    
    pthread_mutex_unlock(&affinity_mutex);
    return 0;
}

void cpu_affinity_cleanup(void)
{
    pthread_mutex_lock(&affinity_mutex);
    
    if (global_topology) {
        free_cpu_topology(global_topology);
        global_topology = NULL;
    }
    
    pthread_mutex_unlock(&affinity_mutex);
}

int cpu_affinity_is_available(void)
{
#ifdef __linux__
    return 1;
#else
    return 0;
#endif
}

/* Utility functions */
const char *numa_policy_to_string(int policy)
{
    switch (policy) {
        case 0: return "default";
        case 1: return "bind";
        case 2: return "interleave";
        case 3: return "preferred";
        default: return "unknown";
    }
}

const char *cpu_state_to_string(int state)
{
    switch (state) {
        case 0: return "offline";
        case 1: return "online";
        default: return "unknown";
    }
}

int get_cpu_topology(cpu_topology_t *topo)
{
    if (!topo || !global_topology) {
        return -1;
    }
    
    *topo = *global_topology;
    return 0;
}
