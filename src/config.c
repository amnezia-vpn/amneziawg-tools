// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <arpa/inet.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>

#include "config.h"
#include "containers.h"
#include "ipc.h"
#include "encoding.h"
#include "ctype.h"

#define COMMENT_CHAR '#'

// Keys that should return empty string instead of NULL when not found
static const char *awg_optional_keys[] = {
	"I1", "I2", "I3", "I4", "I5",
	"J1", "J2", "J3",
	NULL
};

static const char *get_value(const char *line, const char *key)
{
	size_t linelen = strlen(line);
	size_t keylen = strlen(key);

	if (keylen >= linelen)
		return NULL;

	if (strncasecmp(line, key, keylen))
		return NULL;


	return line + keylen;
}

static inline bool parse_port(uint16_t *port, uint32_t *flags, const char *value)
{
	int ret;
	struct addrinfo *resolved;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP,
		.ai_flags = AI_PASSIVE
	};

	if (!strlen(value)) {
		fprintf(stderr, "Unable to parse empty port\n");
		return false;
	}

	ret = getaddrinfo(NULL, value, &hints, &resolved);
	if (ret) {
		fprintf(stderr, "%s: `%s'\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), value);
		return false;
	}

	ret = -1;
	if (resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(struct sockaddr_in)) {
		*port = ntohs(((struct sockaddr_in *)resolved->ai_addr)->sin_port);
		ret = 0;
	} else if (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(struct sockaddr_in6)) {
		*port = ntohs(((struct sockaddr_in6 *)resolved->ai_addr)->sin6_port);
		ret = 0;
	} else
		fprintf(stderr, "Neither IPv4 nor IPv6 address found: `%s'\n", value);

	freeaddrinfo(resolved);
	if (!ret)
		*flags |= WGDEVICE_HAS_LISTEN_PORT;
	return ret == 0;
}

static inline bool parse_fwmark(uint32_t *fwmark, uint32_t *flags, const char *value)
{
	unsigned long ret;
	char *end;
	int base = 10;

	if (!strcasecmp(value, "off")) {
		*fwmark = 0;
		*flags |= WGDEVICE_HAS_FWMARK;
		return true;
	}

	if (!char_is_digit(value[0]))
		goto err;

	if (strlen(value) > 2 && value[0] == '0' && value[1] == 'x')
		base = 16;

	ret = strtoul(value, &end, base);
	if (*end || ret > UINT32_MAX)
		goto err;

	*fwmark = ret;
	*flags |= WGDEVICE_HAS_FWMARK;
	return true;
err:
	fprintf(stderr, "Fwmark is neither 0/off nor 0-0xffffffff: `%s'\n", value);
	return false;
}

static inline bool parse_key(uint8_t key[static WG_KEY_LEN], const char *value)
{
	if (!key_from_base64(key, value)) {
		fprintf(stderr, "Key is not the correct length or format: `%s'\n", value);
		memset(key, 0, WG_KEY_LEN);
		return false;
	}
	return true;
}

static bool parse_keyfile(uint8_t key[static WG_KEY_LEN], const char *path)
{
	FILE *f;
	int c;
	char dst[WG_KEY_LEN_BASE64];
	bool ret = false;

	f = fopen(path, "r");
	if (!f) {
		perror("fopen");
		return false;
	}

	if (fread(dst, WG_KEY_LEN_BASE64 - 1, 1, f) != 1) {
		/* If we're at the end and we didn't read anything, we're /dev/null or an empty file. */
		if (!ferror(f) && feof(f) && !ftell(f)) {
			memset(key, 0, WG_KEY_LEN);
			ret = true;
			goto out;
		}

		fprintf(stderr, "Invalid length key in key file\n");
		goto out;
	}
	dst[WG_KEY_LEN_BASE64 - 1] = '\0';

	while ((c = getc(f)) != EOF) {
		if (!char_is_space(c)) {
			fprintf(stderr, "Found trailing character in key file: `%c'\n", c);
			goto out;
		}
	}
	if (ferror(f) && errno) {
		perror("getc");
		goto out;
	}
	ret = parse_key(key, dst);

out:
	fclose(f);
	return ret;
}

static inline bool parse_ip(struct wgallowedip *allowedip, const char *value)
{
	allowedip->family = AF_UNSPEC;
	if (strchr(value, ':')) {
		if (inet_pton(AF_INET6, value, &allowedip->ip6) == 1)
			allowedip->family = AF_INET6;
	} else {
		if (inet_pton(AF_INET, value, &allowedip->ip4) == 1)
			allowedip->family = AF_INET;
	}
	if (allowedip->family == AF_UNSPEC) {
		fprintf(stderr, "Unable to parse IP address: `%s'\n", value);
		return false;
	}
	return true;
}

static inline int parse_dns_retries(void)
{
	unsigned long ret;
	char *retries = getenv("WG_ENDPOINT_RESOLUTION_RETRIES"), *end;

	if (!retries)
		return 15;
	if (!strcmp(retries, "infinity"))
		return -1;

	ret = strtoul(retries, &end, 10);
	if (*end || ret > INT_MAX) {
		fprintf(stderr, "Unable to parse WG_ENDPOINT_RESOLUTION_RETRIES: `%s'\n", retries);
		exit(1);
	}
	return (int)ret;
}

static inline bool parse_endpoint(struct sockaddr *endpoint, const char *value)
{
	char *mutable = strdup(value);
	char *begin, *end;
	int ret, retries = parse_dns_retries();
	struct addrinfo *resolved;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP
	};
	if (!mutable) {
		perror("strdup");
		return false;
	}
	if (!strlen(value)) {
		free(mutable);
		fprintf(stderr, "Unable to parse empty endpoint\n");
		return false;
	}
	if (mutable[0] == '[') {
		begin = &mutable[1];
		end = strchr(mutable, ']');
		if (!end) {
			free(mutable);
			fprintf(stderr, "Unable to find matching brace of endpoint: `%s'\n", value);
			return false;
		}
		*end++ = '\0';
		if (*end++ != ':' || !*end) {
			free(mutable);
			fprintf(stderr, "Unable to find port of endpoint: `%s'\n", value);
			return false;
		}
	} else {
		begin = mutable;
		end = strrchr(mutable, ':');
		if (!end || !*(end + 1)) {
			free(mutable);
			fprintf(stderr, "Unable to find port of endpoint: `%s'\n", value);
			return false;
		}
		*end++ = '\0';
	}

	#define min(a, b) ((a) < (b) ? (a) : (b))
	for (unsigned int timeout = 1000000;; timeout = min(20000000, timeout * 6 / 5)) {
		ret = getaddrinfo(begin, end, &hints, &resolved);
		if (!ret)
			break;
		/* The set of return codes that are "permanent failures". All other possibilities are potentially transient.
		 *
		 * This is according to https://sourceware.org/glibc/wiki/NameResolver which states:
		 *	"From the perspective of the application that calls getaddrinfo() it perhaps
		 *	 doesn't matter that much since EAI_FAIL, EAI_NONAME and EAI_NODATA are all
		 *	 permanent failure codes and the causes are all permanent failures in the
		 *	 sense that there is no point in retrying later."
		 *
		 * So this is what we do, except FreeBSD removed EAI_NODATA some time ago, so that's conditional.
		 */
		if (ret == EAI_NONAME || ret == EAI_FAIL ||
			#ifdef EAI_NODATA
				ret == EAI_NODATA ||
			#endif
				(retries >= 0 && !retries--)) {
			free(mutable);
			fprintf(stderr, "%s: `%s'\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), value);
			return false;
		}
		fprintf(stderr, "%s: `%s'. Trying again in %.2f seconds...\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), value, timeout / 1000000.0);
		usleep(timeout);
	}

	if ((resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(struct sockaddr_in)) ||
	    (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(struct sockaddr_in6)))
		memcpy(endpoint, resolved->ai_addr, resolved->ai_addrlen);
	else {
		freeaddrinfo(resolved);
		free(mutable);
		fprintf(stderr, "Neither IPv4 nor IPv6 address found: `%s'\n", value);
		return false;
	}
	freeaddrinfo(resolved);
	free(mutable);
	return true;
}

static inline bool parse_persistent_keepalive(uint16_t *interval, uint32_t *flags, const char *value)
{
	unsigned long ret;
	char *end;

	if (!strcasecmp(value, "off")) {
		*interval = 0;
		*flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
		return true;
	}

	if (!char_is_digit(value[0]))
		goto err;

	ret = strtoul(value, &end, 10);
	if (*end || ret > 65535)
		goto err;

	*interval = (uint16_t)ret;
	*flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
	return true;
err:
	fprintf(stderr, "Persistent keepalive interval is neither 0/off nor 1-65535: `%s'\n", value);
	return false;
}

static bool validate_netmask(struct wgallowedip *allowedip)
{
	uint32_t *ip;
	int last;

	switch (allowedip->family) {
		case AF_INET:
			last = 0;
			ip = (uint32_t *)&allowedip->ip4;
			break;
		case AF_INET6:
			last = 3;
			ip = (uint32_t *)&allowedip->ip6;
			break;
		default:
			return true; /* We don't know how to validate it, so say 'okay'. */
	}

	for (int i = last; i >= 0; --i) {
		uint32_t mask = ~0;

		if (allowedip->cidr >= 32 * (i + 1))
			break;
		if (allowedip->cidr > 32 * i)
			mask >>= (allowedip->cidr - 32 * i);
		if (ntohl(ip[i]) & mask)
			return false;
	}

	return true;
}

static inline bool parse_allowedips(struct wgpeer *peer, struct wgallowedip **last_allowedip, const char *value)
{
	struct wgallowedip *allowedip = *last_allowedip, *new_allowedip;
	char *mask, *mutable = strdup(value), *sep, *saved_entry;

	if (!mutable) {
		perror("strdup");
		return false;
	}
	peer->flags |= WGPEER_REPLACE_ALLOWEDIPS;
	if (!strlen(value)) {
		free(mutable);
		return true;
	}
	sep = mutable;
	while ((mask = strsep(&sep, ","))) {
		unsigned long cidr;
		char *end, *ip;

		saved_entry = strdup(mask);
		ip = strsep(&mask, "/");

		new_allowedip = calloc(1, sizeof(*new_allowedip));
		if (!new_allowedip) {
			perror("calloc");
			free(saved_entry);
			free(mutable);
			return false;
		}

		if (!parse_ip(new_allowedip, ip)) {
			free(new_allowedip);
			free(saved_entry);
			free(mutable);
			return false;
		}

		if (mask) {
			if (!char_is_digit(mask[0]))
				goto err;
			cidr = strtoul(mask, &end, 10);
			if (*end || (cidr > 32 && new_allowedip->family == AF_INET) || (cidr > 128 && new_allowedip->family == AF_INET6))
				goto err;
		} else if (new_allowedip->family == AF_INET)
			cidr = 32;
		else if (new_allowedip->family == AF_INET6)
			cidr = 128;
		else
			goto err;
		new_allowedip->cidr = cidr;

		if (!validate_netmask(new_allowedip))
			fprintf(stderr, "Warning: AllowedIP has nonzero host part: %s/%s\n", ip, mask);

		if (allowedip)
			allowedip->next_allowedip = new_allowedip;
		else
			peer->first_allowedip = new_allowedip;
		allowedip = new_allowedip;
		free(saved_entry);
	}
	free(mutable);
	*last_allowedip = allowedip;
	return true;

err:
	free(new_allowedip);
	free(mutable);
	fprintf(stderr, "AllowedIP is not in the correct format: `%s'\n", saved_entry);
	free(saved_entry);
	return false;
}

static inline bool parse_awg_string(char **device_value, const char *name, const char *value) {
    size_t len = strlen(value);
	if (!len) {
		*device_value = "";
		return true;
	}

    if( len >= MAX_AWG_JUNK_LEN) {
		fprintf(stderr, "Unable to process string for: %s; longer than: %d\n", name, MAX_AWG_JUNK_LEN);
		return false;
    }
    *device_value = strdup(value);

    return true;
}

static inline bool parse_uint16(uint16_t *device_value, const char *name, const char *value) {

	if (!strlen(value)) {
		fprintf(stderr, "Unable to parse empty string\n");
		return false;
	}

	char *end;
	uint32_t ret;
	ret = strtoul(value, &end, 10);

	if (*end || ret > UINT16_MAX) {
		fprintf(stderr, "Unable to parse %s: `%s'\n", name, value);
		exit(1);
	}
	*device_value = (uint16_t)ret;
	return true;
}

static inline bool parse_uint32(uint32_t *device_value, const char *name, const char *value) {

	if (!strlen(value)) {
		fprintf(stderr, "Unable to parse empty string\n");
		return false;
	}

	char *end;
	uint64_t ret;
	ret = strtoul(value, &end, 10);
	if (*end || ret > UINT32_MAX) {
		fprintf(stderr, "Unable to parse %s: `%s'\n", name, value);
		exit(1);
	}
	*device_value = (uint32_t)ret;
	return true;
}

static inline bool parse_bool(bool *device_value, const char *name, const char *value) {

	if (!strlen(value)) {
		fprintf(stderr, "Unable to parse empty string\n");
		return false;
	}

	if (!strcasecmp(value, "off")) {
		*device_value = false;
		return true;
	}

	if (!strcasecmp(value, "on")) {
		*device_value = true;
		return true;
	}

	if (!char_is_digit(value[0]))
		goto err;

	char *end;
	uint32_t ret;
	ret = strtoul(value, &end, 10);

	if (*end) {
		fprintf(stderr, "Unable to parse %s: `%s'\n", name, value);
		exit(1);
	}
	*device_value = ret != 0;
	return true;
err:
	fprintf(stderr, "Boolean value is neither on/off nor 0/1: `%s'\n", value);
	return false;
}

static bool process_line(struct config_ctx *ctx, const char *line)
{
	const char *value;
	bool ret = true;

	if (!strcasecmp(line, "[Interface]")) {
		ctx->is_peer_section = false;
		ctx->is_device_section = true;
		return true;
	}
	if (!strcasecmp(line, "[Peer]")) {
		struct wgpeer *new_peer = calloc(1, sizeof(struct wgpeer));

		if (!new_peer) {
			perror("calloc");
			return false;
		}
		ctx->last_allowedip = NULL;
		if (ctx->last_peer)
			ctx->last_peer->next_peer = new_peer;
		else
			ctx->device->first_peer = new_peer;
		ctx->last_peer = new_peer;
		ctx->is_peer_section = true;
		ctx->is_device_section = false;
		ctx->last_peer->flags |= WGPEER_REPLACE_ALLOWEDIPS;
		return true;
	}

#define key_match(key) (value = get_value(line, key "="))

	if (ctx->is_device_section) {
		if (key_match("ListenPort"))
			ret = parse_port(&ctx->device->listen_port, &ctx->device->flags, value);
		else if (key_match("FwMark"))
			ret = parse_fwmark(&ctx->device->fwmark, &ctx->device->flags, value);
		else if (key_match("PrivateKey")) {
			ret = parse_key(ctx->device->private_key, value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_PRIVATE_KEY;
		} else if (key_match("Jc")) {
			ret = parse_uint16(&ctx->device->junk_packet_count, "Jc", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_JC;
		} else if (key_match("Jmin")) {
			ret = parse_uint16(&ctx->device->junk_packet_min_size, "Jmin", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_JMIN;
		} else if (key_match("Jmax")) {
			ret = parse_uint16(&ctx->device->junk_packet_max_size, "Jmax", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_JMAX;
		} else if (key_match("S1")) {
			ret = parse_uint16(&ctx->device->init_packet_junk_size, "S1", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_S1;
		} else if (key_match("S2")) {
			ret = parse_uint16(&ctx->device->response_packet_junk_size, "S2", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_S2;
		} else if (key_match("S3")) {
			ret = parse_uint16(&ctx->device->cookie_reply_packet_junk_size, "S3", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_S3;
		} else if (key_match("S4")) {
			ret = parse_uint16(&ctx->device->transport_packet_junk_size, "S4", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_S4;
		} else if (key_match("H1")) {
			ret = parse_uint32(&ctx->device->init_packet_magic_header, "H1", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_H1;
		} else if (key_match("H2")) {
			ret = parse_uint32(&ctx->device->response_packet_magic_header, "H2", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_H2;
		} else if (key_match("H3")) {
			ret = parse_uint32(&ctx->device->underload_packet_magic_header, "H3", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_H3;
		} else if (key_match("H4")) {
			ret = parse_uint32(&ctx->device->transport_packet_magic_header, "H4", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_H4;
		} else if (key_match("I1")) {
			ret = parse_awg_string(&ctx->device->i1, "I1", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_I1;
		} else if (key_match("I2")) {
			ret = parse_awg_string(&ctx->device->i2, "I2", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_I2;
		} else if (key_match("I3")) {
			ret = parse_awg_string(&ctx->device->i3, "I3", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_I3;
		} else if (key_match("I4")) {
			ret = parse_awg_string(&ctx->device->i4, "I4", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_I4;
		} else if (key_match("I5")) {
			ret = parse_awg_string(&ctx->device->i5, "I5", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_I5;
		} else if (key_match("J1")) {
			ret = parse_awg_string(&ctx->device->j1, "J1", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_J1;
		} else if (key_match("J2")) {
			ret = parse_awg_string(&ctx->device->j2, "J2", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_J2;
		} else if (key_match("J3")) {
			ret = parse_awg_string(&ctx->device->j3, "J3", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_J3;
		} else if (key_match("Itime")) {
			ret = parse_uint32(&ctx->device->itime, "Itime", value);
			if (ret)
				ctx->device->flags |= WGDEVICE_HAS_ITIME;
		} else {
			// Check if this is an AWG optional key
			if (strlen(line) == 3) {
				for (int i = 0; awg_optional_keys[i] != NULL; i++) {
					if (!strncasecmp(line, awg_optional_keys[i], 2))
						return true;
				}
			}
			goto error;
		}
	} else if (ctx->is_peer_section) {
		if (key_match("Endpoint"))
			ret = parse_endpoint(&ctx->last_peer->endpoint.addr, value);
		else if (key_match("PublicKey")) {
			ret = parse_key(ctx->last_peer->public_key, value);
			if (ret)
				ctx->last_peer->flags |= WGPEER_HAS_PUBLIC_KEY;
		} else if (key_match("AllowedIPs"))
			ret = parse_allowedips(ctx->last_peer, &ctx->last_allowedip, value);
		else if (key_match("PersistentKeepalive"))
			ret = parse_persistent_keepalive(&ctx->last_peer->persistent_keepalive_interval, &ctx->last_peer->flags, value);
		else if (key_match("PresharedKey")) {
			ret = parse_key(ctx->last_peer->preshared_key, value);
			if (ret)
				ctx->last_peer->flags |= WGPEER_HAS_PRESHARED_KEY;
		} else if (key_match("AdvancedSecurity")) {
			ret = parse_bool(&ctx->last_peer->advanced_security, "AdvancedSecurity", value);
			if (ret)
				ctx->last_peer->flags |= WGPEER_HAS_ADVANCED_SECURITY;
		} else if (key_match("SpecialHandshake")) {
			ret = parse_bool(&ctx->last_peer->special_handshake, "SpecialHandshake", value);
			if (ret)
				ctx->last_peer->flags |= WGPEER_HAS_SPECIAL_HANDSHAKE;
		} else
			goto error;
	} else
		goto error;
	return ret;

#undef key_match

error:
	fprintf(stderr, "Line unrecognized: `%s'\n", line);
	return false;
}

bool config_read_line(struct config_ctx *ctx, const char *input)
{
	size_t len, cleaned_len = 0;
	char *line, *comment;
	bool ret = true;

	/* This is what strchrnul is for, but that isn't portable. */
	comment = strchr(input, COMMENT_CHAR);
	if (comment)
		len = comment - input;
	else
		len = strlen(input);

	line = calloc(len + 1, sizeof(char));
	if (!line) {
		perror("calloc");
		ret = false;
		goto out;
	}

	for (size_t i = 0; i < len; ++i) {
		if (!char_is_space(input[i]))
			line[cleaned_len++] = input[i];
	}

	if (!cleaned_len)
		goto out;
	ret = process_line(ctx, line);
out:
	free(line);
	if (!ret)
		free_wgdevice(ctx->device);
	return ret;
}

bool config_read_init(struct config_ctx *ctx, bool append)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->device = calloc(1, sizeof(*ctx->device));
	if (!ctx->device) {
		perror("calloc");
		return false;
	}
	if (!append)
		ctx->device->flags |= WGDEVICE_REPLACE_PEERS | WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_FWMARK;
	return true;
}

struct wgdevice *config_read_finish(struct config_ctx *ctx)
{
	struct wgpeer *peer;

	for_each_wgpeer(ctx->device, peer) {
		if (!(peer->flags & WGPEER_HAS_PUBLIC_KEY)) {
			fprintf(stderr, "A peer is missing a public key\n");
			goto err;
		}
	}
	return ctx->device;
err:
	free_wgdevice(ctx->device);
	return NULL;
}

static char *strip_spaces(const char *in)
{
	char *out;
	size_t t, l, i;

	t = strlen(in);
	out = calloc(t + 1, sizeof(char));
	if (!out) {
		perror("calloc");
		return NULL;
	}
	for (i = 0, l = 0; i < t; ++i) {
		if (!char_is_space(in[i]))
			out[l++] = in[i];
	}
	return out;
}

struct wgdevice *config_read_cmd(const char *argv[], int argc)
{
	struct wgdevice *device = calloc(1, sizeof(*device));
	struct wgpeer *peer = NULL;
	struct wgallowedip *allowedip = NULL;

	if (!device) {
		perror("calloc");
		return false;
	}
	while (argc > 0) {
		if (!strcmp(argv[0], "listen-port") && argc >= 2 && !peer) {
			if (!parse_port(&device->listen_port, &device->flags, argv[1]))
				goto error;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "fwmark") && argc >= 2 && !peer) {
			if (!parse_fwmark(&device->fwmark, &device->flags, argv[1]))
				goto error;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "private-key") && argc >= 2 && !peer) {
			if (!parse_keyfile(device->private_key, argv[1]))
				goto error;
			device->flags |= WGDEVICE_HAS_PRIVATE_KEY;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "jc") && argc >= 2 && !peer) {
			if (!parse_uint16(&device->junk_packet_count, "jc", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_JC;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "jmin") && argc >= 2 && !peer) {
			if (!parse_uint16(&device->junk_packet_min_size, "jmin", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_JMIN;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "jmax") && argc >= 2 && !peer) {
			if (!parse_uint16(&device->junk_packet_max_size, "jmax", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_JMAX;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "s1") && argc >= 2 && !peer) {
			if (!parse_uint16(&device->init_packet_junk_size, "s1", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_S1;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "s2") && argc >= 2 && !peer) {
			if (!parse_uint16(&device->response_packet_junk_size, "s2", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_S2;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "s3") && argc >= 2 && !peer) {
			if (!parse_uint16(&device->cookie_reply_packet_junk_size, "s3", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_S3;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "s4") && argc >= 2 && !peer) {
			if (!parse_uint16(&device->transport_packet_junk_size, "s4", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_S4;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "h1") && argc >= 2 && !peer) {
			if (!parse_uint32(&device->init_packet_magic_header, "h1", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_H1;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "h2") && argc >= 2 && !peer) {
			if (!parse_uint32(&device->response_packet_magic_header, "h2", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_H2;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "h3") && argc >= 2 && !peer) {
			if (!parse_uint32(&device->underload_packet_magic_header, "h3", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_H3;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "h4") && argc >= 2 && !peer) {
			if (!parse_uint32(&device->transport_packet_magic_header, "h4", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_H4;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "i1") && argc >= 2 && !peer) {
			if (!parse_awg_string(&device->i1, "i1", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_I1;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "i2") && argc >= 2 && !peer) {
			if (!parse_awg_string(&device->i2, "i2", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_I2;
			argv += 2;
			argc -=2;
		} else if (!strcmp(argv[0], "i3") && argc >= 2 && !peer) {
			if (!parse_awg_string(&device->i3, "i3", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_I3;
			argv += 2;
			argc -=2;
		} else if (!strcmp(argv[0], "i4") && argc >= 2 && !peer) {
			if (!parse_awg_string(&device->i4, "i4", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_I4;
			argv += 2;
			argc -=2;
		} else if (!strcmp(argv[0], "i5") && argc >= 2 && !peer) {
			if (!parse_awg_string(&device->i5, "i5", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_I5;
			argv += 2;
			argc -=2;
		} else if (!strcmp(argv[0], "j1") && argc >= 2 && !peer) {
			if (!parse_awg_string(&device->j1, "j1", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_J1;
			argv += 2;
			argc -=2;
		} else if (!strcmp(argv[0], "j2") && argc >= 2 && !peer) {
			if (!parse_awg_string(&device->j2, "j2", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_J2;
			argv += 2;
			argc -=2;
		} else if (!strcmp(argv[0], "j3") && argc >= 2 && !peer) {
			if (!parse_awg_string(&device->j3, "j3", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_J3;
			argv += 2;
			argc -=2;
		} else if (!strcmp(argv[0], "itime") && argc >= 2 && !peer) {
			if (!parse_uint32(&device->itime, "itime", argv[1]))
				goto error;

			device->flags |= WGDEVICE_HAS_ITIME;
			argv += 2;
			argc -=2;
		} else if (!strcmp(argv[0], "peer") && argc >= 2) {
			struct wgpeer *new_peer = calloc(1, sizeof(*new_peer));

			allowedip = NULL;
			if (!new_peer) {
				perror("calloc");
				goto error;
			}
			if (peer)
				peer->next_peer = new_peer;
			else
				device->first_peer = new_peer;
			peer = new_peer;
			if (!parse_key(peer->public_key, argv[1]))
				goto error;
			peer->flags |= WGPEER_HAS_PUBLIC_KEY;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "remove") && argc >= 1 && peer) {
			peer->flags |= WGPEER_REMOVE_ME;
			argv += 1;
			argc -= 1;
		} else if (!strcmp(argv[0], "endpoint") && argc >= 2 && peer) {
			if (!parse_endpoint(&peer->endpoint.addr, argv[1]))
				goto error;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "allowed-ips") && argc >= 2 && peer) {
			char *line = strip_spaces(argv[1]);

			if (!line)
				goto error;
			if (!parse_allowedips(peer, &allowedip, line)) {
				free(line);
				goto error;
			}
			free(line);
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "persistent-keepalive") && argc >= 2 && peer) {
			if (!parse_persistent_keepalive(&peer->persistent_keepalive_interval, &peer->flags, argv[1]))
				goto error;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "preshared-key") && argc >= 2 && peer) {
			if (!parse_keyfile(peer->preshared_key, argv[1]))
				goto error;
			peer->flags |= WGPEER_HAS_PRESHARED_KEY;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "advanced-security") && argc >= 2 && peer) {
			if (!parse_bool(&peer->advanced_security, "AdvancedSecurity", argv[1]))
				goto error;
			peer->flags |= WGPEER_HAS_ADVANCED_SECURITY;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "special-handshake") && argc >= 2 && peer) {
			if (!parse_bool(&peer->special_handshake, "SpecialHandshake", argv[1]))
				goto error;
			peer->flags |= WGPEER_HAS_SPECIAL_HANDSHAKE;
			argv += 2;
			argc -= 2;
		} else {
			fprintf(stderr, "Invalid argument: %s\n", argv[0]);
			goto error;
		}
	}
	return device;
error:
	free_wgdevice(device);
	return false;
}
