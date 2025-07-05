/*
 * Network I/O Abstraction Layer - AF_XDP (Linux Kernel Bypass)
 * High-performance zero-copy packet processing via AF_XDP sockets
 * 
 * This implementation provides kernel bypass capabilities for maximum
 * performance on Linux systems with AF_XDP support.
 */

#include "nio_af_xdp.h"
#include "buffer_pool.h"
#include "event_loop.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#ifdef HAVE_AF_XDP

/* Check if AF_XDP is available on this system */
static int check_af_xdp_support(void)
{
    int sock = socket(AF_XDP, SOCK_RAW, 0);
    if (sock < 0) {
        return 0; /* AF_XDP not supported */
    }
    close(sock);
    return 1;
}

/* Initialize AF_XDP UMEM (User Memory) */
static int initialize_umem(struct af_xdp_umem *umem, size_t size, size_t frame_count)
{
    /* Allocate memory for UMEM */
    umem->buffer = mmap(NULL, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (umem->buffer == MAP_FAILED) {
        /* Fallback to regular pages if hugepages fail */
        umem->buffer = mmap(NULL, size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (umem->buffer == MAP_FAILED) {
            return -1;
        }
    }
    
    umem->size = size;
    umem->frame_size = size / frame_count;
    umem->frame_count = frame_count;
    
    /* Initialize UMEM configuration */
    struct xdp_umem_reg umem_reg = {
        .addr = (uint64_t)umem->buffer,
        .len = size,
        .chunk_size = umem->frame_size,
        .headroom = XDP_PACKET_HEADROOM,
        .flags = 0
    };
    
    /* Create UMEM socket */
    umem->fd = socket(AF_XDP, SOCK_RAW, 0);
    if (umem->fd < 0) {
        munmap(umem->buffer, size);
        return -1;
    }
    
    /* Register UMEM */
    if (setsockopt(umem->fd, SOL_XDP, XDP_UMEM_REG, &umem_reg, sizeof(umem_reg)) < 0) {
        close(umem->fd);
        munmap(umem->buffer, size);
        return -1;
    }
    
    return 0;
}

/* Initialize AF_XDP ring buffers */
static int initialize_rings(struct af_xdp_socket *xsk)
{
    /* Fill ring configuration */
    struct xdp_ring_offset_v1 fill_offset;
    socklen_t optlen = sizeof(fill_offset);
    if (getsockopt(xsk->umem->fd, SOL_XDP, XDP_UMEM_FILL_RING, &fill_offset, &optlen) < 0) {
        return -1;
    }
    
    /* Completion ring configuration */
    struct xdp_ring_offset_v1 comp_offset;
    optlen = sizeof(comp_offset);
    if (getsockopt(xsk->umem->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &comp_offset, &optlen) < 0) {
        return -1;
    }
    
    /* Map fill ring */
    size_t fill_ring_size = fill_offset.desc + xsk->config.fill_size * sizeof(uint64_t);
    void *fill_map = mmap(NULL, fill_ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, xsk->umem->fd, XDP_UMEM_PGOFF_FILL_RING);
    if (fill_map == MAP_FAILED) {
        return -1;
    }
    
    xsk->fill_ring.producer = (uint32_t *)(fill_map + fill_offset.producer);
    xsk->fill_ring.consumer = (uint32_t *)(fill_map + fill_offset.consumer);
    xsk->fill_ring.flags = (uint32_t *)(fill_map + fill_offset.flags);
    xsk->fill_ring.ring = (uint64_t *)(fill_map + fill_offset.desc);
    xsk->fill_ring.size = xsk->config.fill_size;
    xsk->fill_ring.mask = xsk->config.fill_size - 1;
    
    /* Map completion ring */
    size_t comp_ring_size = comp_offset.desc + xsk->config.comp_size * sizeof(uint64_t);
    void *comp_map = mmap(NULL, comp_ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, xsk->umem->fd, XDP_UMEM_PGOFF_COMPLETION_RING);
    if (comp_map == MAP_FAILED) {
        munmap(fill_map, fill_ring_size);
        return -1;
    }
    
    xsk->comp_ring.producer = (uint32_t *)(comp_map + comp_offset.producer);
    xsk->comp_ring.consumer = (uint32_t *)(comp_map + comp_offset.consumer);
    xsk->comp_ring.flags = (uint32_t *)(comp_map + comp_offset.flags);
    xsk->comp_ring.ring = (uint64_t *)(comp_map + comp_offset.desc);
    xsk->comp_ring.size = xsk->config.comp_size;
    xsk->comp_ring.mask = xsk->config.comp_size - 1;
    
    /* RX ring configuration */
    struct xdp_ring_offset_v1 rx_offset;
    optlen = sizeof(rx_offset);
    if (getsockopt(xsk->fd, SOL_XDP, XDP_RX_RING, &rx_offset, &optlen) < 0) {
        munmap(fill_map, fill_ring_size);
        munmap(comp_map, comp_ring_size);
        return -1;
    }
    
    /* TX ring configuration */
    struct xdp_ring_offset_v1 tx_offset;
    optlen = sizeof(tx_offset);
    if (getsockopt(xsk->fd, SOL_XDP, XDP_TX_RING, &tx_offset, &optlen) < 0) {
        munmap(fill_map, fill_ring_size);
        munmap(comp_map, comp_ring_size);
        return -1;
    }
    
    /* Map RX ring */
    size_t rx_ring_size = rx_offset.desc + xsk->config.rx_size * sizeof(struct xdp_desc);
    void *rx_map = mmap(NULL, rx_ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, xsk->fd, XDP_PGOFF_RX_RING);
    if (rx_map == MAP_FAILED) {
        munmap(fill_map, fill_ring_size);
        munmap(comp_map, comp_ring_size);
        return -1;
    }
    
    xsk->rx_ring.producer = (uint32_t *)(rx_map + rx_offset.producer);
    xsk->rx_ring.consumer = (uint32_t *)(rx_map + rx_offset.consumer);
    xsk->rx_ring.flags = (uint32_t *)(rx_map + rx_offset.flags);
    xsk->rx_ring.ring = (struct xdp_desc *)(rx_map + rx_offset.desc);
    xsk->rx_ring.size = xsk->config.rx_size;
    xsk->rx_ring.mask = xsk->config.rx_size - 1;
    
    /* Map TX ring */
    size_t tx_ring_size = tx_offset.desc + xsk->config.tx_size * sizeof(struct xdp_desc);
    void *tx_map = mmap(NULL, tx_ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, xsk->fd, XDP_PGOFF_TX_RING);
    if (tx_map == MAP_FAILED) {
        munmap(fill_map, fill_ring_size);
        munmap(comp_map, comp_ring_size);
        munmap(rx_map, rx_ring_size);
        return -1;
    }
    
    xsk->tx_ring.producer = (uint32_t *)(tx_map + tx_offset.producer);
    xsk->tx_ring.consumer = (uint32_t *)(tx_map + tx_offset.consumer);
    xsk->tx_ring.flags = (uint32_t *)(tx_map + tx_offset.flags);
    xsk->tx_ring.ring = (struct xdp_desc *)(tx_map + tx_offset.desc);
    xsk->tx_ring.size = xsk->config.tx_size;
    xsk->tx_ring.mask = xsk->config.tx_size - 1;
    
    return 0;
}

/* Create AF_XDP socket */
struct af_xdp_socket *af_xdp_create_socket(const char *interface, int queue_id, struct af_xdp_config *config)
{
    if (!check_af_xdp_support()) {
        return NULL;
    }
    
    struct af_xdp_socket *xsk = calloc(1, sizeof(struct af_xdp_socket));
    if (!xsk) {
        return NULL;
    }
    
    /* Copy configuration */
    if (config) {
        xsk->config = *config;
    } else {
        /* Default configuration */
        xsk->config.rx_size = AF_XDP_DEFAULT_RING_SIZE;
        xsk->config.tx_size = AF_XDP_DEFAULT_RING_SIZE;
        xsk->config.fill_size = AF_XDP_DEFAULT_RING_SIZE;
        xsk->config.comp_size = AF_XDP_DEFAULT_RING_SIZE;
        xsk->config.frame_size = AF_XDP_DEFAULT_FRAME_SIZE;
        xsk->config.flags = 0;
    }
    
    /* Initialize UMEM */
    xsk->umem = calloc(1, sizeof(struct af_xdp_umem));
    if (!xsk->umem) {
        free(xsk);
        return NULL;
    }
    
    size_t umem_size = xsk->config.frame_size * (xsk->config.rx_size + xsk->config.tx_size);
    if (initialize_umem(xsk->umem, umem_size, xsk->config.rx_size + xsk->config.tx_size) < 0) {
        free(xsk->umem);
        free(xsk);
        return NULL;
    }
    
    /* Create XDP socket */
    xsk->fd = socket(AF_XDP, SOCK_RAW, 0);
    if (xsk->fd < 0) {
        af_xdp_destroy_socket(xsk);
        return NULL;
    }
    
    /* Set ring sizes */
    int rx_ring_size = xsk->config.rx_size;
    int tx_ring_size = xsk->config.tx_size;
    int fill_ring_size = xsk->config.fill_size;
    int comp_ring_size = xsk->config.comp_size;
    
    if (setsockopt(xsk->fd, SOL_XDP, XDP_RX_RING, &rx_ring_size, sizeof(rx_ring_size)) < 0 ||
        setsockopt(xsk->fd, SOL_XDP, XDP_TX_RING, &tx_ring_size, sizeof(tx_ring_size)) < 0 ||
        setsockopt(xsk->umem->fd, SOL_XDP, XDP_UMEM_FILL_RING, &fill_ring_size, sizeof(fill_ring_size)) < 0 ||
        setsockopt(xsk->umem->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &comp_ring_size, sizeof(comp_ring_size)) < 0) {
        af_xdp_destroy_socket(xsk);
        return NULL;
    }
    
    /* Initialize rings */
    if (initialize_rings(xsk) < 0) {
        af_xdp_destroy_socket(xsk);
        return NULL;
    }
    
    /* Bind socket to interface */
    struct sockaddr_xdp addr = {
        .sxdp_family = AF_XDP,
        .sxdp_ifindex = if_nametoindex(interface),
        .sxdp_queue_id = queue_id,
        .sxdp_flags = xsk->config.flags
    };
    
    if (bind(xsk->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        af_xdp_destroy_socket(xsk);
        return NULL;
    }
    
    /* Fill the FILL ring with buffers */
    af_xdp_fill_ring_populate(xsk);
    
    strncpy(xsk->interface, interface, sizeof(xsk->interface) - 1);
    xsk->queue_id = queue_id;
    
    return xsk;
}

/* Destroy AF_XDP socket */
void af_xdp_destroy_socket(struct af_xdp_socket *xsk)
{
    if (!xsk) return;
    
    if (xsk->fd >= 0) {
        close(xsk->fd);
    }
    
    if (xsk->umem) {
        if (xsk->umem->fd >= 0) {
            close(xsk->umem->fd);
        }
        if (xsk->umem->buffer != MAP_FAILED && xsk->umem->buffer) {
            munmap(xsk->umem->buffer, xsk->umem->size);
        }
        free(xsk->umem);
    }
    
    free(xsk);
}

/* Populate fill ring with available buffers */
int af_xdp_fill_ring_populate(struct af_xdp_socket *xsk)
{
    uint32_t producer = *xsk->fill_ring.producer;
    uint32_t available = xsk->fill_ring.size - (producer - *xsk->fill_ring.consumer);
    
    if (available == 0) {
        return 0;
    }
    
    /* Add buffers to fill ring */
    for (uint32_t i = 0; i < available; i++) {
        uint64_t addr = i * xsk->config.frame_size;
        xsk->fill_ring.ring[(producer + i) & xsk->fill_ring.mask] = addr;
    }
    
    /* Update producer pointer with memory barrier */
    __sync_synchronize();
    *xsk->fill_ring.producer = producer + available;
    
    return available;
}

/* Receive packets via AF_XDP */
int af_xdp_receive_packets(struct af_xdp_socket *xsk, struct af_xdp_packet *packets, int max_packets)
{
    uint32_t consumer = *xsk->rx_ring.consumer;
    uint32_t producer = *xsk->rx_ring.producer;
    uint32_t available = producer - consumer;
    
    if (available == 0) {
        return 0;
    }
    
    int count = (available > max_packets) ? max_packets : available;
    
    for (int i = 0; i < count; i++) {
        struct xdp_desc *desc = &xsk->rx_ring.ring[(consumer + i) & xsk->rx_ring.mask];
        
        packets[i].addr = desc->addr;
        packets[i].len = desc->len;
        packets[i].data = (char *)xsk->umem->buffer + desc->addr;
    }
    
    /* Update consumer pointer */
    __sync_synchronize();
    *xsk->rx_ring.consumer = consumer + count;
    
    /* Repopulate fill ring */
    af_xdp_fill_ring_populate(xsk);
    
    return count;
}

/* Send packets via AF_XDP */
int af_xdp_send_packets(struct af_xdp_socket *xsk, struct af_xdp_packet *packets, int count)
{
    uint32_t producer = *xsk->tx_ring.producer;
    uint32_t available = xsk->tx_ring.size - (producer - *xsk->tx_ring.consumer);
    
    if (available < count) {
        /* Complete transmitted packets first */
        af_xdp_complete_tx(xsk);
        available = xsk->tx_ring.size - (producer - *xsk->tx_ring.consumer);
        if (available < count) {
            count = available;
        }
    }
    
    /* Add packets to TX ring */
    for (int i = 0; i < count; i++) {
        struct xdp_desc *desc = &xsk->tx_ring.ring[(producer + i) & xsk->tx_ring.mask];
        desc->addr = packets[i].addr;
        desc->len = packets[i].len;
    }
    
    /* Update producer pointer with memory barrier */
    __sync_synchronize();
    *xsk->tx_ring.producer = producer + count;
    
    /* Trigger transmission */
    if (sendto(xsk->fd, NULL, 0, MSG_DONTWAIT, NULL, 0) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return -1;
        }
    }
    
    return count;
}

/* Complete transmitted packets */
int af_xdp_complete_tx(struct af_xdp_socket *xsk)
{
    uint32_t consumer = *xsk->comp_ring.consumer;
    uint32_t producer = *xsk->comp_ring.producer;
    uint32_t completed = producer - consumer;
    
    if (completed == 0) {
        return 0;
    }
    
    /* Process completed packets */
    for (uint32_t i = 0; i < completed; i++) {
        uint64_t addr = xsk->comp_ring.ring[(consumer + i) & xsk->comp_ring.mask];
        /* Buffer is now available for reuse */
        (void)addr; /* Mark as used */
    }
    
    /* Update consumer pointer */
    __sync_synchronize();
    *xsk->comp_ring.consumer = consumer + completed;
    
    return completed;
}

/* Get socket file descriptor for polling */
int af_xdp_get_fd(struct af_xdp_socket *xsk)
{
    return xsk ? xsk->fd : -1;
}

/* Get statistics */
int af_xdp_get_stats(struct af_xdp_socket *xsk, struct af_xdp_stats *stats)
{
    if (!xsk || !stats) {
        return -1;
    }
    
    memset(stats, 0, sizeof(*stats));
    
    /* Get XDP statistics */
    struct xdp_statistics xdp_stats;
    socklen_t optlen = sizeof(xdp_stats);
    if (getsockopt(xsk->fd, SOL_XDP, XDP_STATISTICS, &xdp_stats, &optlen) == 0) {
        stats->rx_packets = xdp_stats.rx_packets;
        stats->tx_packets = xdp_stats.tx_packets;
        stats->rx_dropped = xdp_stats.rx_dropped;
        stats->tx_dropped = xdp_stats.tx_dropped;
        stats->rx_ring_full = xdp_stats.rx_ring_full;
        stats->tx_ring_empty = xdp_stats.tx_ring_empty;
    }
    
    return 0;
}

/* Check if system supports AF_XDP */
int af_xdp_is_supported(void)
{
    return check_af_xdp_support();
}

#else /* !HAVE_AF_XDP */

/* Stub implementations when AF_XDP is not available */
struct af_xdp_socket *af_xdp_create_socket(const char *interface, int queue_id, struct af_xdp_config *config)
{
    (void)interface; (void)queue_id; (void)config;
    return NULL;
}

void af_xdp_destroy_socket(struct af_xdp_socket *xsk)
{
    (void)xsk;
}

int af_xdp_fill_ring_populate(struct af_xdp_socket *xsk)
{
    (void)xsk;
    return 0;
}

int af_xdp_receive_packets(struct af_xdp_socket *xsk, struct af_xdp_packet *packets, int max_packets)
{
    (void)xsk; (void)packets; (void)max_packets;
    return 0;
}

int af_xdp_send_packets(struct af_xdp_socket *xsk, struct af_xdp_packet *packets, int count)
{
    (void)xsk; (void)packets; (void)count;
    return 0;
}

int af_xdp_complete_tx(struct af_xdp_socket *xsk)
{
    (void)xsk;
    return 0;
}

int af_xdp_get_fd(struct af_xdp_socket *xsk)
{
    (void)xsk;
    return -1;
}

int af_xdp_get_stats(struct af_xdp_socket *xsk, struct af_xdp_stats *stats)
{
    (void)xsk; (void)stats;
    return -1;
}

int af_xdp_is_supported(void)
{
    return 0;
}

#endif /* HAVE_AF_XDP */
