/*
 * SIMD Optimizations for uBridge
 * Hardware-accelerated packet processing using SSE/AVX instructions
 * 
 * This module provides vectorized operations for high-performance
 * packet processing, filtering, and memory operations.
 */

#ifndef SIMD_OPTIMIZATIONS_H
#define SIMD_OPTIMIZATIONS_H

#include <stdint.h>
#include <stddef.h>

/* Feature detection */
typedef struct {
    int has_sse2;
    int has_sse4_1;
    int has_avx;
    int has_avx2;
    int has_avx512;
} simd_features_t;

/* SIMD-optimized functions */
typedef struct {
    /* Memory operations */
    void (*memcpy_simd)(void *dst, const void *src, size_t len);
    void (*memset_simd)(void *dst, int value, size_t len);
    int (*memcmp_simd)(const void *s1, const void *s2, size_t len);
    
    /* Checksum operations */
    uint16_t (*checksum_simd)(const void *data, size_t len);
    uint32_t (*crc32_simd)(uint32_t crc, const void *data, size_t len);
    
    /* Packet filtering */
    int (*filter_match_simd)(const void *packet, size_t len, const void *pattern, size_t pattern_len);
    int (*filter_batch_simd)(const void **packets, size_t *lengths, int count, const void *pattern, size_t pattern_len);
    
    /* Packet processing */
    int (*process_batch_simd)(void **packets, size_t *lengths, int count);
    
} simd_ops_t;

/* Global SIMD operations structure */
extern simd_ops_t simd_ops;
extern simd_features_t simd_features;

/* Initialization and feature detection */
int simd_init(void);
void simd_cleanup(void);
const simd_features_t *simd_get_features(void);

/* Runtime feature checks */
static inline int simd_has_sse2(void) { return simd_features.has_sse2; }
static inline int simd_has_sse4_1(void) { return simd_features.has_sse4_1; }
static inline int simd_has_avx(void) { return simd_features.has_avx; }
static inline int simd_has_avx2(void) { return simd_features.has_avx2; }
static inline int simd_has_avx512(void) { return simd_features.has_avx512; }

/* Memory operations with SIMD acceleration */
void simd_memcpy(void *dst, const void *src, size_t len);
void simd_memset(void *dst, int value, size_t len);
int simd_memcmp(const void *s1, const void *s2, size_t len);

/* Checksum operations */
uint16_t simd_checksum(const void *data, size_t len);
uint32_t simd_crc32(uint32_t crc, const void *data, size_t len);

/* Packet filtering with SIMD */
int simd_filter_match(const void *packet, size_t len, const void *pattern, size_t pattern_len);
int simd_filter_batch(const void **packets, size_t *lengths, int count, const void *pattern, size_t pattern_len);

/* Batch packet processing */
int simd_process_batch(void **packets, size_t *lengths, int count);

/* Architecture-specific implementations */
#ifdef __x86_64__
/* SSE2 implementations */
void simd_memcpy_sse2(void *dst, const void *src, size_t len);
void simd_memset_sse2(void *dst, int value, size_t len);
int simd_memcmp_sse2(const void *s1, const void *s2, size_t len);
uint16_t simd_checksum_sse2(const void *data, size_t len);

/* AVX implementations */
void simd_memcpy_avx(void *dst, const void *src, size_t len);
void simd_memset_avx(void *dst, int value, size_t len);
int simd_memcmp_avx(const void *s1, const void *s2, size_t len);
uint16_t simd_checksum_avx(const void *data, size_t len);

/* AVX2 implementations */
void simd_memcpy_avx2(void *dst, const void *src, size_t len);
void simd_memset_avx2(void *dst, int value, size_t len);
int simd_memcmp_avx2(const void *s1, const void *s2, size_t len);
uint16_t simd_checksum_avx2(const void *data, size_t len);
int simd_filter_match_avx2(const void *packet, size_t len, const void *pattern, size_t pattern_len);
int simd_filter_batch_avx2(const void **packets, size_t *lengths, int count, const void *pattern, size_t pattern_len);

#endif /* __x86_64__ */

#ifdef __aarch64__
/* ARM NEON implementations */
void simd_memcpy_neon(void *dst, const void *src, size_t len);
void simd_memset_neon(void *dst, int value, size_t len);
int simd_memcmp_neon(const void *s1, const void *s2, size_t len);
uint16_t simd_checksum_neon(const void *data, size_t len);
#endif /* __aarch64__ */

/* Compiler intrinsics availability */
#ifdef __SSE2__
#define HAVE_SSE2 1
#else
#define HAVE_SSE2 0
#endif

#ifdef __SSE4_1__
#define HAVE_SSE4_1 1
#else
#define HAVE_SSE4_1 0
#endif

#ifdef __AVX__
#define HAVE_AVX 1
#else
#define HAVE_AVX 0
#endif

#ifdef __AVX2__
#define HAVE_AVX2 1
#else
#define HAVE_AVX2 0
#endif

#ifdef __AVX512F__
#define HAVE_AVX512 1
#else
#define HAVE_AVX512 0
#endif

/* Performance configuration */
#define SIMD_ALIGNMENT 32
#define SIMD_MIN_SIZE 64
#define SIMD_BATCH_SIZE 16

/* Alignment macros */
#define SIMD_ALIGNED __attribute__((aligned(SIMD_ALIGNMENT)))
#define SIMD_ALIGN_PTR(ptr) (void *)(((uintptr_t)(ptr) + SIMD_ALIGNMENT - 1) & ~(SIMD_ALIGNMENT - 1))
#define SIMD_IS_ALIGNED(ptr) (((uintptr_t)(ptr) & (SIMD_ALIGNMENT - 1)) == 0)

/* Prefetch macros */
#ifdef __GNUC__
#define SIMD_PREFETCH_READ(ptr) __builtin_prefetch((ptr), 0, 3)
#define SIMD_PREFETCH_WRITE(ptr) __builtin_prefetch((ptr), 1, 3)
#else
#define SIMD_PREFETCH_READ(ptr) do {} while(0)
#define SIMD_PREFETCH_WRITE(ptr) do {} while(0)
#endif

#endif /* SIMD_OPTIMIZATIONS_H */
