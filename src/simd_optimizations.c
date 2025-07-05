/*
 * SIMD Optimizations Implementation
 * Hardware-accelerated packet processing using SSE/AVX instructions
 */

#include "simd_optimizations.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef __x86_64__
#include <cpuid.h>
#include <immintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <avxintrin.h>
#include <avx2intrin.h>
#endif

#ifdef __aarch64__
#include <arm_neon.h>
#endif

/* Global SIMD operations and features */
simd_ops_t simd_ops;
simd_features_t simd_features;

/* Feature detection for x86_64 */
#ifdef __x86_64__
static void detect_x86_features(void)
{
    unsigned int eax, ebx, ecx, edx;
    
    /* Check for CPUID support */
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        memset(&simd_features, 0, sizeof(simd_features));
        return;
    }
    
    /* SSE2 */
    simd_features.has_sse2 = (edx & bit_SSE2) != 0;
    
    /* SSE4.1 */
    simd_features.has_sse4_1 = (ecx & bit_SSE4_1) != 0;
    
    /* AVX */
    simd_features.has_avx = (ecx & bit_AVX) != 0;
    
    /* Check extended features for AVX2 and AVX512 */
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        simd_features.has_avx2 = (ebx & bit_AVX2) != 0;
        simd_features.has_avx512 = (ebx & bit_AVX512F) != 0;
    }
}
#endif

/* Feature detection for ARM */
#ifdef __aarch64__
static void detect_arm_features(void)
{
    /* NEON is standard on AArch64 */
    simd_features.has_sse2 = 1; /* Use this as NEON indicator */
    simd_features.has_sse4_1 = 0;
    simd_features.has_avx = 0;
    simd_features.has_avx2 = 0;
    simd_features.has_avx512 = 0;
}
#endif

/* Generic fallback implementations */
static void fallback_memcpy(void *dst, const void *src, size_t len)
{
    memcpy(dst, src, len);
}

static void fallback_memset(void *dst, int value, size_t len)
{
    memset(dst, value, len);
}

static int fallback_memcmp(const void *s1, const void *s2, size_t len)
{
    return memcmp(s1, s2, len);
}

static uint16_t fallback_checksum(const void *data, size_t len)
{
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;
    
    /* Sum 16-bit words */
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    
    /* Add odd byte if present */
    if (len > 0) {
        sum += *(const uint8_t *)ptr;
    }
    
    /* Fold 32-bit sum to 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

static uint32_t fallback_crc32(uint32_t crc, const void *data, size_t len)
{
    /* Simple CRC32 implementation */
    const uint8_t *ptr = (const uint8_t *)data;
    static const uint32_t crc_table[256] = {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
        0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
        /* ... full table would be here ... */
    };
    
    crc = ~crc;
    for (size_t i = 0; i < len; i++) {
        crc = crc_table[(crc ^ ptr[i]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

static int fallback_filter_match(const void *packet, size_t len, const void *pattern, size_t pattern_len)
{
    if (pattern_len > len) return 0;
    
    const uint8_t *pkt = (const uint8_t *)packet;
    const uint8_t *pat = (const uint8_t *)pattern;
    
    for (size_t i = 0; i <= len - pattern_len; i++) {
        if (memcmp(pkt + i, pat, pattern_len) == 0) {
            return 1;
        }
    }
    return 0;
}

static int fallback_filter_batch(const void **packets, size_t *lengths, int count, const void *pattern, size_t pattern_len)
{
    int matches = 0;
    for (int i = 0; i < count; i++) {
        if (fallback_filter_match(packets[i], lengths[i], pattern, pattern_len)) {
            matches++;
        }
    }
    return matches;
}

static int fallback_process_batch(void **packets, size_t *lengths, int count)
{
    /* Basic packet validation */
    int processed = 0;
    for (int i = 0; i < count; i++) {
        if (packets[i] && lengths[i] > 0) {
            processed++;
        }
    }
    return processed;
}

/* SSE2 implementations */
#ifdef __x86_64__
void simd_memcpy_sse2(void *dst, const void *src, size_t len)
{
    if (len < SIMD_MIN_SIZE || !SIMD_IS_ALIGNED(dst) || !SIMD_IS_ALIGNED(src)) {
        memcpy(dst, src, len);
        return;
    }
    
    char *d = (char *)dst;
    const char *s = (const char *)src;
    
    /* Copy 16-byte chunks with SSE2 */
    while (len >= 16) {
        __m128i data = _mm_load_si128((const __m128i *)s);
        _mm_store_si128((__m128i *)d, data);
        d += 16;
        s += 16;
        len -= 16;
    }
    
    /* Handle remaining bytes */
    if (len > 0) {
        memcpy(d, s, len);
    }
}

void simd_memset_sse2(void *dst, int value, size_t len)
{
    if (len < SIMD_MIN_SIZE || !SIMD_IS_ALIGNED(dst)) {
        memset(dst, value, len);
        return;
    }
    
    char *d = (char *)dst;
    __m128i val = _mm_set1_epi8(value);
    
    /* Set 16-byte chunks with SSE2 */
    while (len >= 16) {
        _mm_store_si128((__m128i *)d, val);
        d += 16;
        len -= 16;
    }
    
    /* Handle remaining bytes */
    if (len > 0) {
        memset(d, value, len);
    }
}

int simd_memcmp_sse2(const void *s1, const void *s2, size_t len)
{
    if (len < SIMD_MIN_SIZE || !SIMD_IS_ALIGNED(s1) || !SIMD_IS_ALIGNED(s2)) {
        return memcmp(s1, s2, len);
    }
    
    const char *p1 = (const char *)s1;
    const char *p2 = (const char *)s2;
    
    /* Compare 16-byte chunks with SSE2 */
    while (len >= 16) {
        __m128i a = _mm_load_si128((const __m128i *)p1);
        __m128i b = _mm_load_si128((const __m128i *)p2);
        __m128i cmp = _mm_cmpeq_epi8(a, b);
        
        if (_mm_movemask_epi8(cmp) != 0xFFFF) {
            /* Found difference, fall back to byte comparison */
            return memcmp(p1, p2, 16);
        }
        
        p1 += 16;
        p2 += 16;
        len -= 16;
    }
    
    /* Handle remaining bytes */
    if (len > 0) {
        return memcmp(p1, p2, len);
    }
    
    return 0;
}

uint16_t simd_checksum_sse2(const void *data, size_t len)
{
    if (len < SIMD_MIN_SIZE || !SIMD_IS_ALIGNED(data)) {
        return fallback_checksum(data, len);
    }
    
    const char *ptr = (const char *)data;
    __m128i sum = _mm_setzero_si128();
    
    /* Process 16-byte chunks */
    while (len >= 16) {
        __m128i chunk = _mm_load_si128((const __m128i *)ptr);
        
        /* Split into 16-bit words and add */
        __m128i low = _mm_unpacklo_epi8(chunk, _mm_setzero_si128());
        __m128i high = _mm_unpackhi_epi8(chunk, _mm_setzero_si128());
        
        sum = _mm_add_epi16(sum, low);
        sum = _mm_add_epi16(sum, high);
        
        ptr += 16;
        len -= 16;
    }
    
    /* Horizontal sum */
    uint16_t result[8];
    _mm_store_si128((__m128i *)result, sum);
    
    uint32_t total = 0;
    for (int i = 0; i < 8; i++) {
        total += result[i];
    }
    
    /* Add remaining bytes */
    while (len > 1) {
        total += *(const uint16_t *)ptr;
        ptr += 2;
        len -= 2;
    }
    
    if (len > 0) {
        total += *(const uint8_t *)ptr;
    }
    
    /* Fold to 16 bits */
    while (total >> 16) {
        total = (total & 0xFFFF) + (total >> 16);
    }
    
    return ~total;
}

/* AVX2 implementations */
#if HAVE_AVX2
void simd_memcpy_avx2(void *dst, const void *src, size_t len)
{
    if (len < SIMD_MIN_SIZE || !SIMD_IS_ALIGNED(dst) || !SIMD_IS_ALIGNED(src)) {
        simd_memcpy_sse2(dst, src, len);
        return;
    }
    
    char *d = (char *)dst;
    const char *s = (const char *)src;
    
    /* Copy 32-byte chunks with AVX2 */
    while (len >= 32) {
        __m256i data = _mm256_load_si256((const __m256i *)s);
        _mm256_store_si256((__m256i *)d, data);
        d += 32;
        s += 32;
        len -= 32;
    }
    
    /* Handle remaining bytes with SSE2 */
    if (len > 0) {
        simd_memcpy_sse2(d, s, len);
    }
}

int simd_filter_match_avx2(const void *packet, size_t len, const void *pattern, size_t pattern_len)
{
    if (pattern_len > len || pattern_len < 16) {
        return fallback_filter_match(packet, len, pattern, pattern_len);
    }
    
    const char *pkt = (const char *)packet;
    const char *pat = (const char *)pattern;
    
    /* Load pattern into AVX2 register */
    __m256i pattern_vec = _mm256_loadu_si256((const __m256i *)pat);
    
    /* Search through packet data */
    for (size_t i = 0; i <= len - pattern_len; i += 32) {
        size_t remaining = len - i;
        if (remaining < 32) break;
        
        __m256i data_vec = _mm256_loadu_si256((const __m256i *)(pkt + i));
        __m256i cmp = _mm256_cmpeq_epi8(data_vec, pattern_vec);
        
        if (_mm256_movemask_epi8(cmp) != 0) {
            /* Potential match found, verify with precise comparison */
            for (size_t j = i; j <= len - pattern_len && j < i + 32; j++) {
                if (memcmp(pkt + j, pat, pattern_len) == 0) {
                    return 1;
                }
            }
        }
    }
    
    return 0;
}

int simd_filter_batch_avx2(const void **packets, size_t *lengths, int count, const void *pattern, size_t pattern_len)
{
    int matches = 0;
    
    /* Process packets in batches for better cache utilization */
    for (int i = 0; i < count; i++) {
        if (simd_filter_match_avx2(packets[i], lengths[i], pattern, pattern_len)) {
            matches++;
        }
    }
    
    return matches;
}
#endif /* HAVE_AVX2 */

#endif /* __x86_64__ */

/* ARM NEON implementations */
#ifdef __aarch64__
void simd_memcpy_neon(void *dst, const void *src, size_t len)
{
    if (len < SIMD_MIN_SIZE || !SIMD_IS_ALIGNED(dst) || !SIMD_IS_ALIGNED(src)) {
        memcpy(dst, src, len);
        return;
    }
    
    char *d = (char *)dst;
    const char *s = (const char *)src;
    
    /* Copy 16-byte chunks with NEON */
    while (len >= 16) {
        uint8x16_t data = vld1q_u8((const uint8_t *)s);
        vst1q_u8((uint8_t *)d, data);
        d += 16;
        s += 16;
        len -= 16;
    }
    
    /* Handle remaining bytes */
    if (len > 0) {
        memcpy(d, s, len);
    }
}

void simd_memset_neon(void *dst, int value, size_t len)
{
    if (len < SIMD_MIN_SIZE || !SIMD_IS_ALIGNED(dst)) {
        memset(dst, value, len);
        return;
    }
    
    char *d = (char *)dst;
    uint8x16_t val = vdupq_n_u8(value);
    
    /* Set 16-byte chunks with NEON */
    while (len >= 16) {
        vst1q_u8((uint8_t *)d, val);
        d += 16;
        len -= 16;
    }
    
    /* Handle remaining bytes */
    if (len > 0) {
        memset(d, value, len);
    }
}

int simd_memcmp_neon(const void *s1, const void *s2, size_t len)
{
    if (len < SIMD_MIN_SIZE || !SIMD_IS_ALIGNED(s1) || !SIMD_IS_ALIGNED(s2)) {
        return memcmp(s1, s2, len);
    }
    
    const char *p1 = (const char *)s1;
    const char *p2 = (const char *)s2;
    
    /* Compare 16-byte chunks with NEON */
    while (len >= 16) {
        uint8x16_t a = vld1q_u8((const uint8_t *)p1);
        uint8x16_t b = vld1q_u8((const uint8_t *)p2);
        uint8x16_t cmp = vceqq_u8(a, b);
        
        /* Check if all bytes are equal */
        if (vminvq_u8(cmp) != 0xFF) {
            /* Found difference, fall back to byte comparison */
            return memcmp(p1, p2, 16);
        }
        
        p1 += 16;
        p2 += 16;
        len -= 16;
    }
    
    /* Handle remaining bytes */
    if (len > 0) {
        return memcmp(p1, p2, len);
    }
    
    return 0;
}

uint16_t simd_checksum_neon(const void *data, size_t len)
{
    if (len < SIMD_MIN_SIZE || !SIMD_IS_ALIGNED(data)) {
        return fallback_checksum(data, len);
    }
    
    const char *ptr = (const char *)data;
    uint32x4_t sum = vdupq_n_u32(0);
    
    /* Process 16-byte chunks */
    while (len >= 16) {
        uint8x16_t chunk = vld1q_u8((const uint8_t *)ptr);
        
        /* Convert to 16-bit and add */
        uint16x8_t low = vmovl_u8(vget_low_u8(chunk));
        uint16x8_t high = vmovl_u8(vget_high_u8(chunk));
        
        sum = vaddw_u16(sum, vget_low_u16(low));
        sum = vaddw_u16(sum, vget_high_u16(low));
        sum = vaddw_u16(sum, vget_low_u16(high));
        sum = vaddw_u16(sum, vget_high_u16(high));
        
        ptr += 16;
        len -= 16;
    }
    
    /* Horizontal sum */
    uint32_t total = vaddvq_u32(sum);
    
    /* Add remaining bytes */
    while (len > 1) {
        total += *(const uint16_t *)ptr;
        ptr += 2;
        len -= 2;
    }
    
    if (len > 0) {
        total += *(const uint8_t *)ptr;
    }
    
    /* Fold to 16 bits */
    while (total >> 16) {
        total = (total & 0xFFFF) + (total >> 16);
    }
    
    return ~total;
}
#endif /* __aarch64__ */

/* Initialize SIMD operations */
int simd_init(void)
{
    /* Detect CPU features */
#ifdef __x86_64__
    detect_x86_features();
#elif defined(__aarch64__)
    detect_arm_features();
#else
    memset(&simd_features, 0, sizeof(simd_features));
#endif
    
    /* Set up function pointers based on available features */
#ifdef __x86_64__
    if (simd_features.has_avx2) {
        simd_ops.memcpy_simd = simd_memcpy_avx2;
        simd_ops.filter_match_simd = simd_filter_match_avx2;
        simd_ops.filter_batch_simd = simd_filter_batch_avx2;
    } else if (simd_features.has_sse2) {
        simd_ops.memcpy_simd = simd_memcpy_sse2;
        simd_ops.memset_simd = simd_memset_sse2;
        simd_ops.memcmp_simd = simd_memcmp_sse2;
        simd_ops.checksum_simd = simd_checksum_sse2;
    }
#elif defined(__aarch64__)
    if (simd_features.has_sse2) { /* NEON indicator */
        simd_ops.memcpy_simd = simd_memcpy_neon;
        simd_ops.memset_simd = simd_memset_neon;
        simd_ops.memcmp_simd = simd_memcmp_neon;
        simd_ops.checksum_simd = simd_checksum_neon;
    }
#endif
    
    /* Set fallbacks for unsupported operations */
    if (!simd_ops.memcpy_simd) simd_ops.memcpy_simd = fallback_memcpy;
    if (!simd_ops.memset_simd) simd_ops.memset_simd = fallback_memset;
    if (!simd_ops.memcmp_simd) simd_ops.memcmp_simd = fallback_memcmp;
    if (!simd_ops.checksum_simd) simd_ops.checksum_simd = fallback_checksum;
    if (!simd_ops.crc32_simd) simd_ops.crc32_simd = fallback_crc32;
    if (!simd_ops.filter_match_simd) simd_ops.filter_match_simd = fallback_filter_match;
    if (!simd_ops.filter_batch_simd) simd_ops.filter_batch_simd = fallback_filter_batch;
    if (!simd_ops.process_batch_simd) simd_ops.process_batch_simd = fallback_process_batch;
    
    return 0;
}

void simd_cleanup(void)
{
    /* Nothing to clean up for now */
}

const simd_features_t *simd_get_features(void)
{
    return &simd_features;
}

/* Public API wrappers */
void simd_memcpy(void *dst, const void *src, size_t len)
{
    simd_ops.memcpy_simd(dst, src, len);
}

void simd_memset(void *dst, int value, size_t len)
{
    simd_ops.memset_simd(dst, value, len);
}

int simd_memcmp(const void *s1, const void *s2, size_t len)
{
    return simd_ops.memcmp_simd(s1, s2, len);
}

uint16_t simd_checksum(const void *data, size_t len)
{
    return simd_ops.checksum_simd(data, len);
}

uint32_t simd_crc32(uint32_t crc, const void *data, size_t len)
{
    return simd_ops.crc32_simd(crc, data, len);
}

int simd_filter_match(const void *packet, size_t len, const void *pattern, size_t pattern_len)
{
    return simd_ops.filter_match_simd(packet, len, pattern, pattern_len);
}

int simd_filter_batch(const void **packets, size_t *lengths, int count, const void *pattern, size_t pattern_len)
{
    return simd_ops.filter_batch_simd(packets, lengths, count, pattern, pattern_len);
}

int simd_process_batch(void **packets, size_t *lengths, int count)
{
    return simd_ops.process_batch_simd(packets, lengths, count);
}
