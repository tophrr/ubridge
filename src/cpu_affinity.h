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

#ifndef CPU_AFFINITY_H_
#define CPU_AFFINITY_H_

#include <sys/types.h>
#include <stdint.h>
#include <time.h>

#ifdef __linux__
#include <sched.h>
#ifdef HAVE_NUMA
#include <numa.h>
#include <numaif.h>
#endif
#endif

/* CPU and NUMA topology information */
typedef struct cpu_topology {
    int num_cpus;               /* Total number of CPUs */
    int num_numa_nodes;         /* Number of NUMA nodes */
    int *cpu_to_node;           /* CPU to NUMA node mapping */
    int **node_cpus;            /* NUMA node to CPU list mapping */
    int *node_cpu_count;        /* Number of CPUs per NUMA node */
    int online_cpus;            /* Number of online CPUs */
    int hyperthreading_enabled; /* Whether hyperthreading is enabled */
} cpu_topology_t;

/* CPU affinity configuration */
typedef struct cpu_affinity_config {
    int enable_affinity;        /* Enable CPU affinity */
    int enable_numa_binding;    /* Enable NUMA memory binding */
    int isolate_event_loop;     /* Isolate event loop to specific CPU */
    int event_loop_cpu;         /* CPU for event loop thread */
    int worker_cpu_start;       /* Starting CPU for worker threads */
    int worker_cpu_count;       /* Number of CPUs for workers */
    int numa_node;              /* Preferred NUMA node */
    int auto_detect;            /* Auto-detect optimal configuration */
} cpu_affinity_config_t;

/* Performance monitoring for CPU affinity */
typedef struct cpu_affinity_stats {
    uint64_t context_switches;  /* Number of context switches */
    uint64_t cache_misses;      /* CPU cache misses */
    uint64_t numa_migrations;   /* NUMA node migrations */
    double cpu_utilization;     /* Average CPU utilization */
    double cache_hit_ratio;     /* CPU cache hit ratio */
    int current_cpu;            /* Current CPU assignment */
    int current_numa_node;      /* Current NUMA node */
    time_t init_time;           /* Initialization timestamp */
} cpu_affinity_stats_t;

/* Global CPU topology information - defined in cpu_affinity.c */
extern cpu_topology_t *global_topology;

/* Function declarations */

/* Initialization and cleanup */
int cpu_affinity_init(void);
void cpu_affinity_cleanup(void);
int cpu_affinity_is_available(void);

/* Topology detection and management */
cpu_topology_t *detect_cpu_topology(void);
int get_cpu_topology(cpu_topology_t *topo);
void free_cpu_topology(cpu_topology_t *topo);
void print_cpu_topology(cpu_topology_t *topo);

/* CPU affinity management */
int set_thread_affinity(pthread_t thread, int cpu);
int set_process_affinity(pid_t pid, int cpu);
int set_affinity_mask(pthread_t thread, cpu_set_t *mask);
int get_current_cpu(void);
int get_current_numa_node(void);

/* NUMA memory management */
int bind_memory_to_node(void *addr, size_t len, int node);
int set_numa_policy(int policy, int node);
void *allocate_numa_memory(size_t size, int node);
void free_numa_memory(void *addr, size_t size);

/* Auto-configuration */
cpu_affinity_config_t *auto_configure_affinity(cpu_topology_t *topo, int num_bridges);
int apply_affinity_config(cpu_affinity_config_t *config, cpu_topology_t *topo);

/* Performance optimization */
int optimize_for_latency(cpu_topology_t *topo);
int optimize_for_throughput(cpu_topology_t *topo);
int isolate_critical_threads(pthread_t *threads, int count, cpu_topology_t *topo);

/* Statistics and monitoring */
void get_affinity_stats(cpu_affinity_stats_t *stats);
void reset_affinity_stats(void);
void print_affinity_stats(cpu_affinity_stats_t *stats);

/* Configuration helpers */
int parse_cpu_list(const char *cpu_list, int *cpus, int max_cpus);
int parse_numa_nodes(const char *node_list, int *nodes, int max_nodes);
void validate_affinity_config(cpu_affinity_config_t *config, cpu_topology_t *topo);

/* Platform-specific implementations */
#ifdef __linux__
int linux_set_cpu_affinity(pthread_t thread, int cpu);
int linux_get_numa_info(cpu_topology_t *topo);
int linux_bind_memory_numa(void *addr, size_t len, int node);
#endif

/* Utility functions */
const char *numa_policy_to_string(int policy);
const char *cpu_state_to_string(int state);

#endif /* !CPU_AFFINITY_H_ */
