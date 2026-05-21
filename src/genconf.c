// SPDX-License-Identifier: GPL-2.0 OR MIT
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "curve25519.h"
#include "encoding.h"
#include "random.h"
#include "subcommands.h"

#define MIN_MAGIC_HEADER 5U
#define MAX_MAGIC_HEADER_OFFSET UINT16_MAX
#define MIN_LISTEN_PORT 1024U
#define MAX_LISTEN_PORT UINT16_MAX

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#define SET_SOCKADDR_LEN(addr) ((addr).sin_len = sizeof(addr))
#define SET_SOCKADDR6_LEN(addr) ((addr).sin6_len = sizeof(addr))
#else
#define SET_SOCKADDR_LEN(addr) do { } while (0)
#define SET_SOCKADDR6_LEN(addr) do { } while (0)
#endif

struct magic_header {
	uint32_t first;
	uint32_t last;
};

#ifndef _WIN32
typedef int socket_fd_t;
#define INVALID_SOCKET_FD (-1)
#define close_socket close
#else
typedef SOCKET socket_fd_t;
#define INVALID_SOCKET_FD INVALID_SOCKET
#define close_socket closesocket
#endif

static bool random_u32(uint32_t *value)
{
	return get_random_bytes((uint8_t *)value, sizeof(*value));
}

static bool random_range_u32(uint32_t *value, uint32_t min, uint32_t max)
{
	uint32_t random, range;
	uint64_t limit;

	if (min > max) {
		errno = ERANGE;
		return false;
	}
	range = max - min + 1;
	if (!range) {
		if (!random_u32(value))
			return false;
		return true;
	}

	limit = ((uint64_t)UINT32_MAX + 1) - (((uint64_t)UINT32_MAX + 1) % range);
	do {
		if (!random_u32(&random))
			return false;
	} while ((uint64_t)random >= limit);

	*value = min + (random % range);
	return true;
}

static bool random_magic_header(struct magic_header *header)
{
	uint32_t offset;

	if (!random_range_u32(&header->first, MIN_MAGIC_HEADER, UINT32_MAX))
		return false;
	if (!random_range_u32(&offset, 0, MAX_MAGIC_HEADER_OFFSET))
		return false;

	header->last = header->first + offset;
	if (header->last < header->first)
		header->last = UINT32_MAX;
	return true;
}

static bool magic_headers_overlap(const struct magic_header *a, const struct magic_header *b)
{
	return a->last >= b->first && b->last >= a->first;
}

static bool any_magic_headers_overlap(const struct magic_header headers[static 4])
{
	for (size_t i = 0; i < 4; ++i) {
		for (size_t j = i + 1; j < 4; ++j) {
			if (magic_headers_overlap(&headers[i], &headers[j]))
				return true;
		}
	}
	return false;
}

static bool udp_port_available_ipv4(uint16_t port)
{
	socket_fd_t fd;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr = { 0 }
	};
	bool available;

	SET_SOCKADDR_LEN(addr);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == INVALID_SOCKET_FD)
		return false;

	available = bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0;
	close_socket(fd);
	return available;
}

static bool udp_port_available_ipv6(uint16_t port)
{
	socket_fd_t fd;
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
		.sin6_addr = IN6ADDR_ANY_INIT
	};
	bool available;

	SET_SOCKADDR6_LEN(addr);
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd == INVALID_SOCKET_FD)
		return true;

	available = bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0;
	close_socket(fd);
	return available;
}

static bool random_available_listen_port(uint32_t *port)
{
	for (size_t attempt = 0; attempt < 128; ++attempt) {
		if (!random_range_u32(port, MIN_LISTEN_PORT, MAX_LISTEN_PORT))
			return false;
		if (udp_port_available_ipv4((uint16_t)*port) && udp_port_available_ipv6((uint16_t)*port))
			return true;
	}

	errno = EADDRINUSE;
	return false;
}

int genconf_main(int argc, const char *argv[])
{
	uint8_t key[WG_KEY_LEN];
	char base64[WG_KEY_LEN_BASE64];
	uint32_t listen_port, jc, jmin, jmax, s1, s2, s3, s4;
	struct magic_header h[4];
	bool found_nonoverlapping_headers = false;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s %s\n", PROG_NAME, argv[0]);
		return 1;
	}

	if (!get_random_bytes(key, WG_KEY_LEN)) {
		perror("getrandom");
		return 1;
	}
	curve25519_clamp_secret(key);
	key_to_base64(base64, key);

	if (!random_available_listen_port(&listen_port)) {
		perror("listen port");
		return 1;
	}
	if (!random_range_u32(&jc, 3, 10) ||
	    !random_range_u32(&jmin, 0, 1200) ||
	    !random_range_u32(&jmax, jmin, 1280) ||
	    !random_range_u32(&s1, 15, 1304) ||
	    !random_range_u32(&s2, 15, 1360) ||
	    !random_range_u32(&s3, 15, 1388) ||
	    !random_range_u32(&s4, 15, 160)) {
		perror("getrandom");
		return 1;
	}

	for (size_t attempt = 0; attempt < 128; ++attempt) {
		if (!random_magic_header(&h[0]) ||
		    !random_magic_header(&h[1]) ||
		    !random_magic_header(&h[2]) ||
		    !random_magic_header(&h[3])) {
			perror("getrandom");
			return 1;
		}
		if (!any_magic_headers_overlap(h)) {
			found_nonoverlapping_headers = true;
			break;
		}
	}
	if (!found_nonoverlapping_headers) {
		fputs("Unable to generate non-overlapping magic headers\n", stderr);
		return 1;
	}

	printf("[Interface]\n");
	printf("ListenPort = %" PRIu32 "\n", listen_port);
	printf("PrivateKey = %s\n", base64);
	printf("Jc = %" PRIu32 "\n", jc);
	printf("Jmin = %" PRIu32 "\n", jmin);
	printf("Jmax = %" PRIu32 "\n", jmax);
	printf("S1 = %" PRIu32 "\n", s1);
	printf("S2 = %" PRIu32 "\n", s2);
	printf("S3 = %" PRIu32 "\n", s3);
	printf("S4 = %" PRIu32 "\n", s4);
	printf("H1 = %" PRIu32 "-%" PRIu32 "\n", h[0].first, h[0].last);
	printf("H2 = %" PRIu32 "-%" PRIu32 "\n", h[1].first, h[1].last);
	printf("H3 = %" PRIu32 "-%" PRIu32 "\n", h[2].first, h[2].last);
	printf("H4 = %" PRIu32 "-%" PRIu32 "\n", h[3].first, h[3].last);
	return 0;
}
