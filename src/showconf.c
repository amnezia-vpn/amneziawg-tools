// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>

#include "containers.h"
#include "encoding.h"
#include "ipc.h"
#include "subcommands.h"

int showconf_main(int argc, const char *argv[])
{
	char base64[WG_KEY_LEN_BASE64];
	char ip[INET6_ADDRSTRLEN];
	struct wgdevice *device = NULL;
	struct wgpeer *peer;
	struct wgallowedip *allowedip;
	int ret = 1;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s %s <interface>\n", PROG_NAME, argv[0]);
		return 1;
	}

	if (ipc_get_device(&device, argv[1])) {
		perror("Unable to access interface");
		goto cleanup;
	}

	printf("[Interface]\n");
	if (device->listen_port)
		printf("ListenPort = %u\n", device->listen_port);
	if (device->fwmark)
		printf("FwMark = 0x%x\n", device->fwmark);
	if (device->flags & WGDEVICE_HAS_PRIVATE_KEY) {
		key_to_base64(base64, device->private_key);
		printf("PrivateKey = %s\n", base64);
	}
	if (device->flags & WGDEVICE_HAS_JC)
		printf("Jc = %u\n", device->junk_packet_count);
	if (device->flags & WGDEVICE_HAS_JMIN)
		printf("Jmin = %u\n", device->junk_packet_min_size);
	if (device->flags & WGDEVICE_HAS_JMAX)
		printf("Jmax = %u\n", device->junk_packet_max_size);
	if (device->flags & WGDEVICE_HAS_S1)
		printf("S1 = %u\n", device->init_packet_junk_size);
	if (device->flags & WGDEVICE_HAS_S2)
		printf("S2 = %u\n", device->response_packet_junk_size);
	if (device->flags & WGDEVICE_HAS_S3)
		printf("S3 = %u\n", device->cookie_reply_packet_junk_size);
	if (device->flags & WGDEVICE_HAS_S4)
		printf("S4 = %u\n", device->transport_packet_junk_size);
	if (device->flags & WGDEVICE_HAS_H1)
		printf("H1 = %u\n", device->init_packet_magic_header);
	if (device->flags & WGDEVICE_HAS_H2)
		printf("H2 = %u\n", device->response_packet_magic_header);
	if (device->flags & WGDEVICE_HAS_H3)
		printf("H3 = %u\n", device->underload_packet_magic_header);
	if (device->flags & WGDEVICE_HAS_H4)
		printf("H4 = %u\n", device->transport_packet_magic_header);
	if (device->flags & WGDEVICE_HAS_I1)
		printf("I1 = %s\n", device->i1);
	if (device->flags & WGDEVICE_HAS_I2)
		printf("I2 = %s\n", device->i2);
	if (device->flags & WGDEVICE_HAS_I3)
		printf("I3 = %s\n", device->i3);
	if (device->flags & WGDEVICE_HAS_I4)
		printf("I4 = %s\n", device->i4);
	if (device->flags & WGDEVICE_HAS_I5)
		printf("I5 = %s\n", device->i5);
	if (device->flags & WGDEVICE_HAS_J1)
		printf("J1 = %s\n", device->j1);
	if (device->flags & WGDEVICE_HAS_J2)
		printf("J2 = %s\n", device->j2);
	if (device->flags & WGDEVICE_HAS_J3)
		printf("J3 = %s\n", device->j3);
	if (device->flags & WGDEVICE_HAS_ITIME)
		printf("Itime = %u\n", device->itime);

	printf("\n");
	for_each_wgpeer(device, peer) {
		key_to_base64(base64, peer->public_key);
		printf("[Peer]\nPublicKey = %s\n", base64);
		if (peer->flags & WGPEER_HAS_PRESHARED_KEY) {
			key_to_base64(base64, peer->preshared_key);
			printf("PresharedKey = %s\n", base64);
		}
		if (peer->flags & WGPEER_HAS_ADVANCED_SECURITY) {
			printf("AdvancedSecurity = %s\n", peer->advanced_security ? "on" : "off");
		}
		if (peer->flags & WGPEER_HAS_SPECIAL_HANDSHAKE) {
			printf("SpecialHandshake = %s\n", peer->special_handshake ? "on" : "off");
		}
		if (peer->first_allowedip)
			printf("AllowedIPs = ");
		for_each_wgallowedip(peer, allowedip) {
			if (allowedip->family == AF_INET) {
				if (!inet_ntop(AF_INET, &allowedip->ip4, ip, INET6_ADDRSTRLEN))
					continue;
			} else if (allowedip->family == AF_INET6) {
				if (!inet_ntop(AF_INET6, &allowedip->ip6, ip, INET6_ADDRSTRLEN))
					continue;
			} else
				continue;
			printf("%s/%d", ip, allowedip->cidr);
			if (allowedip->next_allowedip)
				printf(", ");
		}
		if (peer->first_allowedip)
			printf("\n");

		if (peer->endpoint.addr.sa_family == AF_INET || peer->endpoint.addr.sa_family == AF_INET6) {
			char host[4096 + 1];
			char service[512 + 1];
			socklen_t addr_len = 0;

			if (peer->endpoint.addr.sa_family == AF_INET)
				addr_len = sizeof(struct sockaddr_in);
			else if (peer->endpoint.addr.sa_family == AF_INET6)
				addr_len = sizeof(struct sockaddr_in6);
			if (!getnameinfo(&peer->endpoint.addr, addr_len, host, sizeof(host), service, sizeof(service), NI_DGRAM | NI_NUMERICSERV | NI_NUMERICHOST)) {
				if (peer->endpoint.addr.sa_family == AF_INET6 && strchr(host, ':'))
					printf("Endpoint = [%s]:%s\n", host, service);
				else
					printf("Endpoint = %s:%s\n", host, service);
			}
		}

		if (peer->persistent_keepalive_interval)
			printf("PersistentKeepalive = %u\n", peer->persistent_keepalive_interval);

		if (peer->next_peer)
			printf("\n");
	}
	ret = 0;

cleanup:
	free_wgdevice(device);
	return ret;
}
