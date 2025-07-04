// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "containers.h"
#include "config.h"
#include "ipc.h"
#include "subcommands.h"

int set_main(int argc, const char *argv[])
{
	struct wgdevice *device = NULL;
	int ret = 1;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s %s <interface> [listen-port <port>] [fwmark <mark>] [private-key <file path>] [jc <junk_count>] [jmin <min_value>] [jmax <max_value>] [s1 <init_junk>] [s2 <resp_junk>] [h1 <init_header>] [h2 <resp_header>] [h3 <cookie_header>] [h4 <transp_header>] [i1 \"<taged_junk>\"] [i2 \"<taged_junk>\"] [i3 \"<taged_junk>\"] [i4 \"<taged_junk>\"] [i5 \"<taged_junk>\"] [j1 \"<taged_junk>\"] [j2 \"<taged_junk>\"] [j3 \"<taged_junk>\"] [itime <itimeout>][peer <base64 public key> [remove] [preshared-key <file path>] [endpoint <ip>:<port>] [persistent-keepalive <interval seconds>] [allowed-ips <ip1>/<cidr1>[,<ip2>/<cidr2>] [advanced-security <on|off>]...] ]...\n", PROG_NAME, argv[0]);
		return 1;
	}

	device = config_read_cmd(argv + 2, argc - 2);
	if (!device)
		goto cleanup;
	strncpy(device->name, argv[1], IFNAMSIZ -  1);
	device->name[IFNAMSIZ - 1] = '\0';

	if (ipc_set_device(device) != 0) {
		perror("Unable to modify interface");
		goto cleanup;
	}

	ret = 0;

cleanup:
	free_wgdevice(device);
	return ret;
}
