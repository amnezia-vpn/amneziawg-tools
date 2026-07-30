#include "type.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

bool u32_range_from_string(u32_range_t *range, const char *str) {
    unsigned long lo, hi;
    char *end;

    lo = strtoul(str, &end, 10);
    if (end == str || lo > UINT32_MAX)
        return false;

    if (*end) {
        if (*end != '-')
            return false;
        hi = strtoul(end + 1, &end, 10);
        if (*end || hi > UINT32_MAX || hi < lo)
            return false;
    } else {
        hi = lo;
    }

    *range = u32_range_init(lo, hi);
    return true;
}

const char *u32_range_to_string(u32_range_t range) {
    static char buf[22];

    if (u32_range_lo(range) == u32_range_hi(range))
        sprintf(buf, "%u", u32_range_lo(range));
    else
        sprintf(buf, "%u-%u", u32_range_lo(range), u32_range_hi(range));

    return buf;
}

int u16_range_from_string(u16_range_t *range, const char *str) {
    unsigned long lo, hi;
    char *end;

    lo = strtoul(str, &end, 10);
    if (end == str || lo > UINT32_MAX)
        return false;

    if (*end) {
        if (*end != '-')
            return false;
        hi = strtoul(end + 1, &end, 10);
        if (*end || hi > UINT32_MAX || hi < lo)
            return false;
    } else {
        hi = lo;
    }

    *range = u16_range_init(lo, hi);
    return true;
}

const char *u16_range_to_string(u16_range_t range) {
    static char buf[12];

    if (u16_range_lo(range) == u16_range_hi(range))
        sprintf(buf, "%u", u16_range_lo(range));
    else
        sprintf(buf, "%u-%u", u16_range_lo(range), u16_range_hi(range));

    return buf;
}
