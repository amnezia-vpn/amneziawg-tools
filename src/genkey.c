// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#include "curve25519.h"
#include "encoding.h"
#include "random.h"
#include "subcommands.h"

int genkey_main(int argc, const char *argv[])
{
	uint8_t key[WG_KEY_LEN];
	char base64[WG_KEY_LEN_BASE64];
	struct stat stat;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s %s\n", PROG_NAME, argv[0]);
		return 1;
	}

	if (!fstat(STDOUT_FILENO, &stat) && S_ISREG(stat.st_mode) && stat.st_mode & S_IRWXO)
		fputs("Warning: writing to world accessible file.\nConsider setting the umask to 077 and trying again.\n", stderr);

	if (!get_random_bytes(key, WG_KEY_LEN)) {
		perror("getrandom");
		return 1;
	}
	if (!strcmp(argv[0], "genkey"))
		curve25519_clamp_secret(key);

	key_to_base64(base64, key);
	puts(base64);
	return 0;
}
