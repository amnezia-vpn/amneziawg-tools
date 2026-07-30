#ifndef TYPE_H
#define TYPE_H

#include <stdint.h>
#include <stdbool.h>

typedef uint64_t u32_range_t;

static inline u32_range_t u32_range_init(uint64_t lo, uint64_t hi) {
    return (u32_range_t)((uint64_t)(hi)<<32 | (uint64_t)(lo));
}

static inline uint32_t u32_range_lo(u32_range_t range) {
    return (uint32_t)(range);
}

static inline uint32_t u32_range_hi(u32_range_t range) {
    return (uint32_t)(range>>32);
}

static inline bool u32_range_is_zero(u32_range_t range) {
    return range == 0;
}

static inline bool u32_range_overlap(u32_range_t left, u32_range_t right) {
    return u32_range_lo(left) <= u32_range_hi(right) && u32_range_lo(right) <= u32_range_hi(left);
}

bool u32_range_from_string(u32_range_t *range, const char *str);
const char *u32_range_to_string(u32_range_t range);

typedef uint32_t u16_range_t;

static inline u16_range_t u16_range_init(uint16_t lo, uint16_t hi) {
    return (u16_range_t)((uint32_t)(hi)<<16 | (uint32_t)(lo));
}

static inline uint16_t u16_range_lo(u16_range_t range) {
    return (uint16_t)(range);
}

static inline uint16_t u16_range_hi(u16_range_t range) {
    return (uint16_t)(range>>16);
}

static inline bool u16_range_is_zero(u16_range_t range) {
    return range == 0;
}

static inline bool u16_range_overlap(u16_range_t left, u16_range_t right) {
    return u16_range_lo(left) <= u16_range_hi(right) && u16_range_lo(right) <= u16_range_hi(left);
}

int u16_range_from_string(u16_range_t *range, const char *str);
const char *u16_range_to_string(u16_range_t range);

#endif
