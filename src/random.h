/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef RANDOM_H
#define RANDOM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool get_random_bytes(uint8_t *out, size_t len);

#endif
