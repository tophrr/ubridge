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

#ifndef NIO_AF_XDP_H_
#define NIO_AF_XDP_H_

#include "nio.h"

#ifdef __linux__
#ifdef HAVE_AF_XDP
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <bpf/xsk.h>
#include <bpf/bpf.h>
#else
/* Minimal XDP definitions when full support is not available */
#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

/* Minimal structure definitions for compilation */
struct sockaddr_xdp {
    uint16_t sxdp_family;
    uint16_t sxdp_flags;
    uint32_t sxdp_ifindex;
    uint32_t sxdp_queue_id;
    uint32_t sxdp_shared_umem_fd;
};

struct xdp_desc {
    uint64_t addr;
    uint32_t len;
    uint32_t options;
};

/* Ring structures for when BPF library is not available */
struct af_xdp_ring_cons {
    uint32_t cached_prod;
    uint32_t cached_cons;
    uint32_t mask;
    uint32_t size;
    uint32_t *producer;
    uint32_t *consumer;
    void *ring;
    uint32_t *flags;
};

struct af_xdp_ring_prod {
    uint32_t cached_prod;
    uint32_t cached_cons;
    uint32_t mask;
    uint32_t size;
    uint32_t *producer;
    uint32_t *consumer;
    void *ring;
    uint32_t *flags;
};

/* Define minimum constants needed */
#define XDP_UMEM_REG                1
#define XDP_RX_RING                 2
#define XDP_TX_RING                 3
#define XDP_UMEM_FILL_RING          4
#define XDP_UMEM_COMPLETION_RING    5
#define XDP_STATISTICS              6

#define XDP_PGOFF_RX_RING           0
#define XDP_PGOFF_TX_RING           0x80000000
#define XDP_UMEM_PGOFF_FILL_RING    0x100000000ULL
#define XDP_UMEM_PGOFF_COMPLETION_RING 0x180000000ULL

#define XDP_PACKET_HEADROOM         256

struct xdp_umem_reg {
    uint64_t addr;
    uint64_t len;
    uint32_t chunk_size;
    uint32_t headroom;
    uint32_t flags;
};

struct xdp_statistics {
    uint64_t rx_dropped;
    uint64_t rx_invalid_descs;
    uint64_t tx_invalid_descs;
    uint64_t rx_ring_full;
    uint64_t rx_fill_ring_empty_descs;
    uint64_t tx_ring_empty_descs;
    uint64_t rx_packets;
    uint64_t tx_packets;
};

struct xdp_ring_offset_v1 {
    uint64_t producer;
    uint64_t consumer;
    uint64_t desc;
    uint64_t flags;
};
#endif

#include <sys/mman.h>
#include <net/if.h>
#endif

/* AF_XDP configuration constants */
#define XDP_UMEM_NUM_FRAMES     4096    /* Number of frames in UMEM */
#define XDP_UMEM_FRAME_SIZE     2048    /* Size of each frame */
#define XDP_RING_SIZE           2048    /* Ring buffer size */
#define XDP_BATCH_SIZE          64      /* Batch processing size */

/* AF_XDP socket modes */
typedef enum {
    XDP_MODE_SKB = 0,       /* Generic XDP mode (slower, more compatible) */
    XDP_MODE_DRV,           /* Driver mode (faster, requires driver support) */
    XDP_MODE_HW             /* Hardware offload (fastest, requires HW support) */
} xdp_mode_t;

/* AF_XDP UMEM (User Memory) configuration */
typedef struct xdp_umem {
    void *buffer;           /* UMEM buffer */
    size_t size;            /* Total UMEM size */
    uint32_t frame_size;    /* Size of each frame */
    uint32_t num_frames;    /* Number of frames */
#ifdef HAVE_AF_XDP
    struct xsk_umem *umem;  /* libxdp UMEM handle */
#else
    int fd;                 /* UMEM file descriptor */
#endif
    
    /* Completion queue */
#ifdef HAVE_AF_XDP
    struct xsk_ring_cons cq;
#else
    struct af_xdp_ring_cons cq;
#endif
    
    /* Fill queue */
#ifdef HAVE_AF_XDP
    struct xsk_ring_prod fq;
#else
    struct af_xdp_ring_prod fq;
#endif
} xdp_umem_t;

/* AF_XDP socket structure */
typedef struct xdp_socket {
    int fd;                 /* Socket file descriptor */
#ifdef HAVE_AF_XDP
    struct xsk_socket *xsk; /* libxdp socket handle */
#endif
    
    /* Ring buffers */
#ifdef HAVE_AF_XDP
    struct xsk_ring_cons rx;    /* RX ring (consumer) */
    struct xsk_ring_prod tx;    /* TX ring (producer) */
#else
    struct af_xdp_ring_cons rx; /* RX ring (consumer) */
    struct af_xdp_ring_prod tx; /* TX ring (producer) */
#endif
    
    /* Configuration */
    char ifname[IFNAMSIZ];      /* Interface name */
    int ifindex;                /* Interface index */
    int queue_id;               /* Queue ID */
    xdp_mode_t mode;            /* XDP mode */
    
    /* Shared UMEM */
    xdp_umem_t *umem;
    
    /* Statistics */
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_dropped;
    uint64_t tx_failed;
} xdp_socket_t;

/* AF_XDP NIO implementation */
typedef struct nio_af_xdp {
    char *ifname;               /* Interface name */
    int queue_id;               /* Queue ID to bind to */
    xdp_mode_t mode;            /* XDP mode */
    xdp_socket_t *socket;       /* XDP socket */
    xdp_umem_t *umem;          /* Shared UMEM */
    
    /* Configuration */
    int zero_copy;              /* Enable zero-copy mode */
    int need_wakeup;            /* Use need_wakeup feature */
    int batch_size;             /* Batch processing size */
    
    /* BPF program */
    int prog_fd;                /* BPF program file descriptor */
    char *prog_path;            /* Path to BPF program */
} nio_af_xdp_data_t;

/* Function declarations */

/* AF_XDP NIO management */
nio_t *create_af_xdp(char *ifname, int queue_id, xdp_mode_t mode);
void free_af_xdp(nio_t *nio);

/* AF_XDP socket operations */
xdp_socket_t *create_xdp_socket(const char *ifname, int queue_id, 
                                xdp_mode_t mode, xdp_umem_t *umem);
void destroy_xdp_socket(xdp_socket_t *socket);

/* UMEM management */
xdp_umem_t *create_xdp_umem(uint32_t num_frames, uint32_t frame_size);
void destroy_xdp_umem(xdp_umem_t *umem);

/* Packet I/O operations */
ssize_t af_xdp_recv(nio_t *nio, void *pkt, size_t max_len);
ssize_t af_xdp_send(nio_t *nio, void *pkt, size_t len);

/* Batch operations */
int af_xdp_recv_batch(nio_t *nio, void **pkts, size_t *lens, int max_batch);
int af_xdp_send_batch(nio_t *nio, void **pkts, size_t *lens, int count);

/* BPF program management */
int load_xdp_program(const char *prog_path, const char *ifname);
int unload_xdp_program(const char *ifname);

/* Configuration and tuning */
int configure_xdp_socket(xdp_socket_t *socket, int zero_copy, int need_wakeup);
int tune_xdp_performance(xdp_socket_t *socket);

/* Statistics and monitoring */
void get_xdp_stats(xdp_socket_t *socket, struct xdp_statistics *stats);
void print_xdp_stats(xdp_socket_t *socket);

/* Utility functions */
int get_interface_index(const char *ifname);
int check_xdp_support(const char *ifname);
const char *xdp_mode_to_string(xdp_mode_t mode);

/* Error handling */
void log_xdp_error(const char *function, const char *message);

#endif /* NIO_AF_XDP_H_ */
