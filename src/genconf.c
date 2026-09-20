// SPDX-License-Identifier: GPL-2.0 OR MIT
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
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
#define MIN_HEADER_PROTECTION_PADDING 12U
#define MIN_HANDSHAKE_PADDING 15U
#define MAX_HANDSHAKE_PADDING 150U
#define MAX_S3 64U
#define MAX_S4 32U
#define MAX_JUNK_PACKET_SIZE 1280U
#define HANDSHAKE_SIZE_DELTA 56U

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

static void usage(const char *cmd)
{
	fprintf(stderr, "Usage: %s %s [-v1|-v2|-v3]\n", PROG_NAME, cmd);
}

static bool parse_version_arg(const char *arg, int *version)
{
	if (!strcmp(arg, "1") || !strcmp(arg, "-v1") || !strcmp(arg, "-v=1"))
		*version = 1;
	else if (!strcmp(arg, "2") || !strcmp(arg, "-v2") || !strcmp(arg, "-v=2"))
		*version = 2;
	else if (!strcmp(arg, "3") || !strcmp(arg, "-v3") || !strcmp(arg, "-v=3"))
		*version = 3;
	else
		return false;
	return true;
}

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

static bool random_span_range(uint32_t *lo, uint32_t *hi, uint32_t min_lo, uint32_t max_lo,
			      uint32_t min_span, uint32_t max_span)
{
	uint32_t span;

	if (!random_range_u32(lo, min_lo, max_lo) ||
	    !random_range_u32(&span, min_span, max_span))
		return false;
	*hi = *lo + span;
	return true;
}

static bool random_magic_header(struct magic_header *header, bool as_range)
{
	uint32_t offset;

	if (!random_range_u32(&header->first, MIN_MAGIC_HEADER, UINT32_MAX))
		return false;
	if (!as_range) {
		header->last = header->first;
		return true;
	}
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

static void print_u32_range(const char *name, uint32_t lo, uint32_t hi)
{
	if (lo == hi)
		printf("%s = %" PRIu32 "\n", name, lo);
	else
		printf("%s = %" PRIu32 "-%" PRIu32 "\n", name, lo, hi);
}

static void print_magic_header(const char *name, const struct magic_header *header)
{
	print_u32_range(name, header->first, header->last);
}

int genconf_main(int argc, const char *argv[])
{
	uint8_t key[WG_KEY_LEN];
	char base64[WG_KEY_LEN_BASE64];
	uint32_t listen_port, jc, jmin, jmax, s1, s2, s3, s4;
	uint32_t content_lo, content_hi;
	uint32_t rekey_lo, rekey_hi, reject_lo, reject_hi;
	uint32_t rekey_timeout_lo, rekey_timeout_hi;
	uint32_t keepalive_lo, keepalive_hi, attempts_lo, attempts_hi;
	struct magic_header h[4];
	bool found_headers = false;
	int version = 3, parsed_version;

	for (int i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
		}
		if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
			if (i + 1 >= argc || !parse_version_arg(argv[++i], &parsed_version)) {
				usage(argv[0]);
				return 1;
			}
			version = parsed_version;
			continue;
		}
		if (parse_version_arg(argv[i], &parsed_version)) {
			version = parsed_version;
			continue;
		}
		usage(argv[0]);
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

	if (!random_range_u32(&jc, 4, 12) ||
	    !random_span_range(&jmin, &jmax, 40, 200, 50, 400)) {
		perror("getrandom");
		return 1;
	}
	if (jmax > MAX_JUNK_PACKET_SIZE)
		jmax = MAX_JUNK_PACKET_SIZE;

	if (version >= 3) {
		/* Header protection needs S1-S4 >= 12. RandomTrailers needs them
		 * equal so packet types are not misclassified by size. S4 <= 32. */
		if (!random_range_u32(&s1, MIN_HEADER_PROTECTION_PADDING, MAX_S4)) {
			perror("getrandom");
			return 1;
		}
		s2 = s3 = s4 = s1;
	} else {
		if (!random_range_u32(&s1, MIN_HANDSHAKE_PADDING, MAX_HANDSHAKE_PADDING) ||
		    !random_range_u32(&s2, MIN_HANDSHAKE_PADDING, MAX_HANDSHAKE_PADDING)) {
			perror("getrandom");
			return 1;
		}
		while (s1 + HANDSHAKE_SIZE_DELTA == s2) {
			if (!random_range_u32(&s2, MIN_HANDSHAKE_PADDING, MAX_HANDSHAKE_PADDING)) {
				perror("getrandom");
				return 1;
			}
		}
		if (version >= 2) {
			if (!random_range_u32(&s3, MIN_HANDSHAKE_PADDING, MAX_S3) ||
			    !random_range_u32(&s4, MIN_HANDSHAKE_PADDING, MAX_S4)) {
				perror("getrandom");
				return 1;
			}
		}
	}

	if (version >= 3) {
		if (!random_span_range(&content_lo, &content_hi, 8, 24, 8, 40) ||
		    !random_span_range(&rekey_lo, &rekey_hi, 100, 120, 10, 40) ||
		    !random_range_u32(&reject_lo, rekey_hi + 30, rekey_hi + 60) ||
		    !random_range_u32(&reject_hi, reject_lo + 30, reject_lo + 90) ||
		    !random_span_range(&rekey_timeout_lo, &rekey_timeout_hi, 3, 6, 1, 4) ||
		    !random_span_range(&keepalive_lo, &keepalive_hi, 8, 12, 2, 8) ||
		    !random_span_range(&attempts_lo, &attempts_hi, 15, 25, 5, 25)) {
			perror("getrandom");
			return 1;
		}
		if (content_hi > MAX_S3)
			content_hi = MAX_S3;
	}

	for (size_t attempt = 0; attempt < 128; ++attempt) {
		if (!random_magic_header(&h[0], version == 2) ||
		    !random_magic_header(&h[1], version == 2) ||
		    !random_magic_header(&h[2], version == 2) ||
		    !random_magic_header(&h[3], version == 2)) {
			perror("getrandom");
			return 1;
		}
		if (!any_magic_headers_overlap(h)) {
			found_headers = true;
			break;
		}
	}
	if (!found_headers) {
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
	if (version >= 2) {
		printf("S3 = %" PRIu32 "\n", s3);
		printf("S4 = %" PRIu32 "\n", s4);
	}
	print_magic_header("H1", &h[0]);
	print_magic_header("H2", &h[1]);
	print_magic_header("H3", &h[2]);
	print_magic_header("H4", &h[3]);

	if (version >= 3) {
		if (!get_random_bytes(key, WG_KEY_LEN)) {
			perror("getrandom");
			return 1;
		}
		key_to_base64(base64, key);
		printf("HeaderProtectionKey = %s\n", base64);
		print_u32_range("ContentPaddingAddition", content_lo, content_hi);
		print_u32_range("RekeyAfterTime", rekey_lo, rekey_hi);
		print_u32_range("RekeyTimeout", rekey_timeout_lo, rekey_timeout_hi);
		print_u32_range("RejectAfterTime", reject_lo, reject_hi);
		print_u32_range("KeepaliveTimeout", keepalive_lo, keepalive_hi);
		print_u32_range("MaxHandshakeAttempts", attempts_lo, attempts_hi);
		printf("RandomTrailers = on\n");
		printf("DisableCookies = on\n");
	}
	return 0;
}
