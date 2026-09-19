// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 */

#include <assert.h>
#include <sys/nv.h>
#include <sys/sockio.h>
#include <dev/wg/if_wg.h>

#define IPC_SUPPORTS_KERNEL_INTERFACE

#define WG_FREEBSD_MAX_AWG_STRING_LEN 4097

static int get_dgram_socket(void)
{
	static int sock = -1;
	if (sock < 0)
		sock = socket(AF_INET, SOCK_DGRAM, 0);
	return sock;
}

static uint32_t kernel_get_awg_version(const char *ifname)
{
	struct wg_data_io wgd = { 0 };
	nvlist_t *nvl = NULL;
	int s = get_dgram_socket();
	int saved_errno;
	uint32_t version = WG_AWG_VERSION_2;

	if (s < 0)
		return version;
	strlcpy(wgd.wgd_name, ifname, sizeof(wgd.wgd_name));
	saved_errno = errno;
	if (ioctl(s, SIOCGWG, &wgd) < 0 || !wgd.wgd_size)
		goto out;
	wgd.wgd_data = malloc(wgd.wgd_size);
	if (!wgd.wgd_data)
		goto out;
	if (ioctl(s, SIOCGWG, &wgd) < 0)
		goto out;
	nvl = nvlist_unpack(wgd.wgd_data, wgd.wgd_size, 0);
	if (nvl && nvlist_exists_number(nvl, "awg-version")) {
		uint64_t number = nvlist_get_number(nvl, "awg-version");
		if (number > 0 && number <= UINT32_MAX)
			version = number;
	}
out:
	if (nvl)
		nvlist_destroy(nvl);
	free(wgd.wgd_data);
	errno = saved_errno;
	return version;
}

static int kernel_get_wireguard_interfaces(struct string_list *list)
{
	struct ifgroupreq ifgr = { .ifgr_name = "wg" };
	struct ifg_req *ifg;
	int s = get_dgram_socket(), ret = 0;

	if (s < 0)
		return -errno;

	if (ioctl(s, SIOCGIFGMEMB, (caddr_t)&ifgr) < 0)
		return errno == ENOENT ? 0 : -errno;

	ifgr.ifgr_groups = calloc(1, ifgr.ifgr_len);
	if (!ifgr.ifgr_groups)
		return -errno;
	if (ioctl(s, SIOCGIFGMEMB, (caddr_t)&ifgr) < 0) {
		ret = -errno;
		goto out;
	}

	for (ifg = ifgr.ifgr_groups; ifg && ifgr.ifgr_len > 0; ++ifg) {
		if ((ret = string_list_add(list, ifg->ifgrq_member)) < 0)
			goto out;
		ifgr.ifgr_len -= sizeof(struct ifg_req);
	}

out:
	free(ifgr.ifgr_groups);
	return ret;
}

static int kernel_get_device(struct wgdevice **device, const char *ifname)
{
	struct wg_data_io wgd = { 0 };
	nvlist_t *nvl_device = NULL;
	const nvlist_t *const *nvl_peers;
	struct wgdevice *dev = NULL;
	size_t size, peer_count, i;
	uint64_t number;
	const void *binary;
	int ret = 0, s;
	uint32_t version = WG_AWG_VERSION_2;

	*device = NULL;
	s = get_dgram_socket();
	if (s < 0)
		goto err;

	strlcpy(wgd.wgd_name, ifname, sizeof(wgd.wgd_name));
	if (ioctl(s, SIOCGWG, &wgd) < 0)
		goto err;

	wgd.wgd_data = malloc(wgd.wgd_size);
	if (!wgd.wgd_data)
		goto err;
	if (ioctl(s, SIOCGWG, &wgd) < 0)
		goto err;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		goto err;
	/* The FreeBSD kernel uses zero as an internal sentinel for an unset Hx.
	 * Expose the effective WireGuard message types expected by shared UI code. */
	dev->init_header = u32_range_init(1, 1);
	dev->resp_header = u32_range_init(2, 2);
	dev->cookie_header = u32_range_init(3, 3);
	dev->transport_header = u32_range_init(4, 4);
	strlcpy(dev->name, ifname, sizeof(dev->name));
	nvl_device = nvlist_unpack(wgd.wgd_data, wgd.wgd_size, 0);
	if (!nvl_device)
		goto err;
	if (nvlist_exists_number(nvl_device, "awg-version")) {
		number = nvlist_get_number(nvl_device, "awg-version");
		if (number > 0 && number <= UINT32_MAX)
			version = number;
	}

	if (nvlist_exists_number(nvl_device, "listen-port")) {
		number = nvlist_get_number(nvl_device, "listen-port");
		if (number <= UINT16_MAX) {
			dev->listen_port = number;
			dev->flags |= WGDEVICE_HAS_LISTEN_PORT;
		}
	}
	if (nvlist_exists_number(nvl_device, "jc")) {
		number = nvlist_get_number(nvl_device, "jc");
		if (number <= UINT16_MAX){
			dev->junk_packet_count = number;
			dev->flags |= WGDEVICE_HAS_JC;
		}
	}
	if (nvlist_exists_number(nvl_device, "jmin")) {
		number = nvlist_get_number(nvl_device, "jmin");
		if (number <= UINT16_MAX){
			dev->junk_packet_min_size = number;
			dev->flags |= WGDEVICE_HAS_JMIN;
		}
	}
	if (nvlist_exists_number(nvl_device, "jmax")) {
		number = nvlist_get_number(nvl_device, "jmax");
		if (number <= UINT16_MAX){
			dev->junk_packet_max_size = number;
			dev->flags |= WGDEVICE_HAS_JMAX;
		}
	}
	if (nvlist_exists_number(nvl_device, "s1")) {
		number = nvlist_get_number(nvl_device, "s1");
		if (number <= UINT16_MAX){
			dev->init_packet_junk_size = number;
			dev->flags |= WGDEVICE_HAS_S1;
		}
	}
	if (nvlist_exists_number(nvl_device, "s2")) {
		number = nvlist_get_number(nvl_device, "s2");
		if (number <= UINT16_MAX){
			dev->response_packet_junk_size = number;
			dev->flags |= WGDEVICE_HAS_S2;
		}
	}
	if (nvlist_exists_number(nvl_device, "s3")) {
		number = nvlist_get_number(nvl_device, "s3");
		if (number <= UINT16_MAX){
			dev->cookie_reply_packet_junk_size = number;
			dev->flags |= WGDEVICE_HAS_S3;
		}
	}
	if (nvlist_exists_number(nvl_device, "s4")) {
		number = nvlist_get_number(nvl_device, "s4");
		if (number <= UINT16_MAX){
			dev->transport_packet_junk_size = number;
			dev->flags |= WGDEVICE_HAS_S4;
		}
	}
	{
		static const char *const names[] = { "h1", "h2", "h3", "h4" };
		u32_range_t *const ranges[] = { &dev->init_header, &dev->resp_header,
			&dev->cookie_header, &dev->transport_header };
		const uint32_t flags[] = { WGDEVICE_HAS_H1, WGDEVICE_HAS_H2,
			WGDEVICE_HAS_H3, WGDEVICE_HAS_H4 };

		for (i = 0; i < 4; ++i) {
			if (version >= WG_AWG_VERSION_3 && nvlist_exists_number(nvl_device, names[i])) {
				*ranges[i] = nvlist_get_number(nvl_device, names[i]);
				dev->flags |= flags[i];
			} else if (nvlist_exists_binary(nvl_device, names[i])) {
				binary = nvlist_get_binary(nvl_device, names[i], &size);
				if (binary && size && ((const char *)binary)[size - 1] == '\0' &&
				    u32_range_from_string(ranges[i], binary))
					dev->flags |= flags[i];
			}
		}
	}
	if (nvlist_exists_binary(nvl_device, "i1"))
	{
		binary = nvlist_get_binary(nvl_device, "i1", &size);
		if (binary && size && size <= WG_FREEBSD_MAX_AWG_STRING_LEN && ((const char *)binary)[size - 1] == '\0')
		{
			dev->i1 = strdup((const char*)binary);
			if (!dev->i1) {
				ret = ENOMEM;
				goto err;
			}
			dev->flags |= WGDEVICE_HAS_I1;
		}
	}
	if (nvlist_exists_binary(nvl_device, "i2"))
	{
		binary = nvlist_get_binary(nvl_device, "i2", &size);
		if (binary && size && size <= WG_FREEBSD_MAX_AWG_STRING_LEN && ((const char *)binary)[size - 1] == '\0')
		{
			dev->i2 = strdup((const char*)binary);
			if (!dev->i2) {
				ret = ENOMEM;
				goto err;
			}
			dev->flags |= WGDEVICE_HAS_I2;
		}
	}
	if (nvlist_exists_binary(nvl_device, "i3"))
	{
		binary = nvlist_get_binary(nvl_device, "i3", &size);
		if (binary && size && size <= WG_FREEBSD_MAX_AWG_STRING_LEN && ((const char *)binary)[size - 1] == '\0')
		{
			dev->i3 = strdup((const char*)binary);
			if (!dev->i3) {
				ret = ENOMEM;
				goto err;
			}
			dev->flags |= WGDEVICE_HAS_I3;
		}
	}
	if (nvlist_exists_binary(nvl_device, "i4"))
	{
		binary = nvlist_get_binary(nvl_device, "i4", &size);
		if (binary && size && size <= WG_FREEBSD_MAX_AWG_STRING_LEN && ((const char *)binary)[size - 1] == '\0')
		{
			dev->i4 = strdup((const char*)binary);
			if (!dev->i4) {
				ret = ENOMEM;
				goto err;
			}
			dev->flags |= WGDEVICE_HAS_I4;
		}
	}
	if (nvlist_exists_binary(nvl_device, "i5"))
	{
		binary = nvlist_get_binary(nvl_device, "i5", &size);
		if (binary && size && size <= WG_FREEBSD_MAX_AWG_STRING_LEN && ((const char *)binary)[size - 1] == '\0')
		{
			dev->i5 = strdup((const char*)binary);
			if (!dev->i5) {
				ret = ENOMEM;
				goto err;
			}
			dev->flags |= WGDEVICE_HAS_I5;
		}
	}
	if (version >= WG_AWG_VERSION_3) {
		struct {
			const char *name;
			u16_range_t *range;
			uint32_t flag;
		} range_params[] = {
			{ "content-padding-addition", &dev->content_padding_addition, WGDEVICE_HAS_CONTENT_PADDING_ADDITION },
			{ "rekey-after-time", &dev->rekey_after_time, WGDEVICE_HAS_REKEY_AFTER_TIME },
			{ "rekey-timeout", &dev->rekey_timeout, WGDEVICE_HAS_REKEY_TIMEOUT },
			{ "reject-after-time", &dev->reject_after_time, WGDEVICE_HAS_REJECT_AFTER_TIME },
			{ "keepalive-timeout", &dev->keepalive_timeout, WGDEVICE_HAS_KEEPALIVE_TIMEOUT },
			{ "max-handshake-attempts", &dev->max_handshake_attempts, WGDEVICE_HAS_MAX_HANDSHAKE_ATTEMPTS },
		};

		if (nvlist_exists_binary(nvl_device, "header-protection-key")) {
			binary = nvlist_get_binary(nvl_device, "header-protection-key", &size);
			if (binary && size == sizeof(dev->header_protection_key)) {
				memcpy(dev->header_protection_key, binary, size);
				dev->flags |= WGDEVICE_HAS_HEADER_PROTECTION_KEY;
			}
		}
		for (i = 0; i < sizeof(range_params) / sizeof(range_params[0]); ++i) {
			if (nvlist_exists_number(nvl_device, range_params[i].name) &&
			    (number = nvlist_get_number(nvl_device, range_params[i].name)) <= UINT32_MAX) {
				*range_params[i].range = number;
				dev->flags |= range_params[i].flag;
			}
		}
		if (nvlist_exists_bool(nvl_device, "random-trailers")) {
			dev->random_trailers = nvlist_get_bool(nvl_device, "random-trailers");
			dev->flags |= WGDEVICE_HAS_RANDOM_TRAILERS;
		}
		if (nvlist_exists_bool(nvl_device, "disable-cookies")) {
			dev->disable_cookies = nvlist_get_bool(nvl_device, "disable-cookies");
			dev->flags |= WGDEVICE_HAS_DISABLE_COOKIES;
		}
	}

	if (nvlist_exists_number(nvl_device, "user-cookie")) {
		number = nvlist_get_number(nvl_device, "user-cookie");
		if (number <= UINT32_MAX) {
			dev->fwmark = number;
			dev->flags |= WGDEVICE_HAS_FWMARK;
		}
	}
	if (nvlist_exists_binary(nvl_device, "public-key")) {
		binary = nvlist_get_binary(nvl_device, "public-key", &size);
		if (binary && size == sizeof(dev->public_key)) {
			memcpy(dev->public_key, binary, sizeof(dev->public_key));
			dev->flags |= WGDEVICE_HAS_PUBLIC_KEY;
		}
	}
	if (nvlist_exists_binary(nvl_device, "private-key")) {
		binary = nvlist_get_binary(nvl_device, "private-key", &size);
		if (binary && size == sizeof(dev->private_key)) {
			memcpy(dev->private_key, binary, sizeof(dev->private_key));
			dev->flags |= WGDEVICE_HAS_PRIVATE_KEY;
		}
	}
	if (!nvlist_exists_nvlist_array(nvl_device, "peers"))
		goto skip_peers;
	nvl_peers = nvlist_get_nvlist_array(nvl_device, "peers", &peer_count);
	if (!nvl_peers)
		goto skip_peers;
	for (i = 0; i < peer_count; ++i) {
		struct wgpeer *peer;
		struct wgallowedip *aip = NULL;
		const nvlist_t *const *nvl_aips;
		size_t aip_count, j;

		peer = calloc(1, sizeof(*peer));
		if (!peer)
			goto err_peer;
		if (nvlist_exists_binary(nvl_peers[i], "public-key")) {
			binary = nvlist_get_binary(nvl_peers[i], "public-key", &size);
			if (binary && size == sizeof(peer->public_key)) {
				memcpy(peer->public_key, binary, sizeof(peer->public_key));
				peer->flags |= WGPEER_HAS_PUBLIC_KEY;
			}
		}
		if (nvlist_exists_binary(nvl_peers[i], "preshared-key")) {
			binary = nvlist_get_binary(nvl_peers[i], "preshared-key", &size);
			if (binary && size == sizeof(peer->preshared_key)) {
				memcpy(peer->preshared_key, binary, sizeof(peer->preshared_key));
				if (!key_is_zero(peer->preshared_key))
					peer->flags |= WGPEER_HAS_PRESHARED_KEY;
			}
		}
		if (nvlist_exists_number(nvl_peers[i], "persistent-keepalive-interval")) {
			number = nvlist_get_number(nvl_peers[i], "persistent-keepalive-interval");
			if (number <= UINT32_MAX) {
				peer->persistent_keepalive_interval = version >= WG_AWG_VERSION_3 &&
					number > UINT16_MAX ? number : u16_range_init(number, number);
				peer->flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
			}
		}
		if (nvlist_exists_binary(nvl_peers[i], "endpoint")) {
			const struct sockaddr *endpoint = nvlist_get_binary(nvl_peers[i], "endpoint", &size);
			if (endpoint && size <= sizeof(peer->endpoint) && size >= sizeof(peer->endpoint.addr) &&
			    (endpoint->sa_family == AF_INET || endpoint->sa_family == AF_INET6))
				memcpy(&peer->endpoint.addr, endpoint, size);
		}
		if (nvlist_exists_number(nvl_peers[i], "rx-bytes"))
			peer->rx_bytes = nvlist_get_number(nvl_peers[i], "rx-bytes");
		if (nvlist_exists_number(nvl_peers[i], "tx-bytes"))
			peer->tx_bytes = nvlist_get_number(nvl_peers[i], "tx-bytes");
		if (nvlist_exists_binary(nvl_peers[i], "last-handshake-time")) {
			binary = nvlist_get_binary(nvl_peers[i], "last-handshake-time", &size);
			if (binary && size == sizeof(peer->last_handshake_time))
				memcpy(&peer->last_handshake_time, binary, sizeof(peer->last_handshake_time));
		}

		if (!nvlist_exists_nvlist_array(nvl_peers[i], "allowed-ips"))
			goto skip_allowed_ips;
		nvl_aips = nvlist_get_nvlist_array(nvl_peers[i], "allowed-ips", &aip_count);
		if (!aip_count || !nvl_aips)
			goto skip_allowed_ips;
		for (j = 0; j < aip_count; ++j) {
			if (!nvlist_exists_number(nvl_aips[j], "cidr"))
				continue;
			if (!nvlist_exists_binary(nvl_aips[j], "ipv4") && !nvlist_exists_binary(nvl_aips[j], "ipv6"))
				continue;
			aip = calloc(1, sizeof(*aip));
			if (!aip)
				goto err_allowed_ips;
			number = nvlist_get_number(nvl_aips[j], "cidr");
			if (nvlist_exists_binary(nvl_aips[j], "ipv4")) {
				binary = nvlist_get_binary(nvl_aips[j], "ipv4", &size);
				if (!binary || number > 32) {
					ret = EINVAL;
					goto err_allowed_ips;
				}
				aip->family = AF_INET;
				aip->cidr = number;
				memcpy(&aip->ip4, binary, sizeof(aip->ip4));
			} else {
				assert(nvlist_exists_binary(nvl_aips[j], "ipv6"));
				binary = nvlist_get_binary(nvl_aips[j], "ipv6", &size);
				if (!binary || number > 128) {
					ret = EINVAL;
					goto err_allowed_ips;
				}
				aip->family = AF_INET6;
				aip->cidr = number;
				memcpy(&aip->ip6, binary, sizeof(aip->ip6));
			}

			if (!peer->first_allowedip)
				peer->first_allowedip = aip;
			else
				peer->last_allowedip->next_allowedip = aip;
			peer->last_allowedip = aip;
			aip = NULL;
			continue;

		err_allowed_ips:
			if (!ret)
				ret = -errno;
			free(aip);
			goto err_peer;
		}

		/* Nothing leaked, hopefully -- ownership transferred or aip freed. */
		assert(aip == NULL);
	skip_allowed_ips:
		if (!dev->first_peer)
			dev->first_peer = peer;
		else
			dev->last_peer->next_peer = peer;
		dev->last_peer = peer;
		continue;

	err_peer:
		if (!ret)
			ret = -errno;
		free(peer);
		goto err;
	}

skip_peers:
	free(wgd.wgd_data);
	nvlist_destroy(nvl_device);
	*device = dev;
	return 0;

err:
	if (!ret)
		ret = -errno;
	free(wgd.wgd_data);
	nvlist_destroy(nvl_device);
	free(dev);
	return ret;
}


static int kernel_set_device(struct wgdevice *dev)
{
	struct wg_data_io wgd = { 0 };
	nvlist_t *nvl_device = NULL, **nvl_peers = NULL;
	size_t peer_count = 0, i = 0;
	struct wgpeer *peer;
	int ret = 0, s;
	uint32_t version = kernel_get_awg_version(dev->name);
	const uint32_t awg3_flags = WGDEVICE_HAS_HEADER_PROTECTION_KEY |
		WGDEVICE_HAS_CONTENT_PADDING_ADDITION | WGDEVICE_HAS_REKEY_AFTER_TIME |
		WGDEVICE_HAS_REKEY_TIMEOUT | WGDEVICE_HAS_REJECT_AFTER_TIME |
		WGDEVICE_HAS_KEEPALIVE_TIMEOUT | WGDEVICE_HAS_MAX_HANDSHAKE_ATTEMPTS |
		WGDEVICE_HAS_RANDOM_TRAILERS |
		WGDEVICE_HAS_DISABLE_COOKIES;

	if (version < WG_AWG_VERSION_3 && (dev->flags & awg3_flags)) {
		errno = EOPNOTSUPP;
		return -errno;
	}
	if (version < WG_AWG_VERSION_3) {
		for_each_wgpeer(dev, peer) {
			if ((peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL) &&
			    u16_range_lo(peer->persistent_keepalive_interval) !=
			    u16_range_hi(peer->persistent_keepalive_interval)) {
				errno = EOPNOTSUPP;
				return -errno;
			}
		}
	}

	strlcpy(wgd.wgd_name, dev->name, sizeof(wgd.wgd_name));

	nvl_device = nvlist_create(0);
	if (!nvl_device)
		goto err;

	for_each_wgpeer(dev, peer)
		++peer_count;
	if (peer_count) {
		nvl_peers = calloc(peer_count, sizeof(*nvl_peers));
		if (!nvl_peers)
			goto err;
	}
	if (dev->flags & WGDEVICE_HAS_PRIVATE_KEY)
		nvlist_add_binary(nvl_device, "private-key", dev->private_key, sizeof(dev->private_key));
	if (dev->flags & WGDEVICE_HAS_LISTEN_PORT)
		nvlist_add_number(nvl_device, "listen-port", dev->listen_port);
	if (dev->flags & WGDEVICE_HAS_JC)
		nvlist_add_number(nvl_device, "jc", dev->junk_packet_count);
	if (dev->flags & WGDEVICE_HAS_JMIN)
		nvlist_add_number(nvl_device, "jmin", dev->junk_packet_min_size);
	if (dev->flags & WGDEVICE_HAS_JMAX)
		nvlist_add_number(nvl_device, "jmax", dev->junk_packet_max_size);
	if (dev->flags & WGDEVICE_HAS_S1)
		nvlist_add_number(nvl_device, "s1", dev->init_packet_junk_size);
	if (dev->flags & WGDEVICE_HAS_S2)
		nvlist_add_number(nvl_device, "s2", dev->response_packet_junk_size);
	if (dev->flags & WGDEVICE_HAS_S3)
		nvlist_add_number(nvl_device, "s3", dev->cookie_reply_packet_junk_size);
	if (dev->flags & WGDEVICE_HAS_S4)
		nvlist_add_number(nvl_device, "s4", dev->transport_packet_junk_size);
	{
		static const char *const names[] = { "h1", "h2", "h3", "h4" };
		const u32_range_t ranges[] = { dev->init_header, dev->resp_header,
			dev->cookie_header, dev->transport_header };
		const uint32_t flags[] = { WGDEVICE_HAS_H1, WGDEVICE_HAS_H2,
			WGDEVICE_HAS_H3, WGDEVICE_HAS_H4 };

		for (size_t h = 0; h < 4; ++h) {
			if (!(dev->flags & flags[h]))
				continue;
			if (version >= WG_AWG_VERSION_3)
				nvlist_add_number(nvl_device, names[h], ranges[h]);
			else {
				const char *value = u32_range_to_string(ranges[h]);
				nvlist_add_binary(nvl_device, names[h], value, strlen(value) + 1);
			}
		}
	}
	if (dev->flags & WGDEVICE_HAS_I1)
		nvlist_add_binary(nvl_device, "i1", dev->i1, strlen(dev->i1) + 1);
	if (dev->flags & WGDEVICE_HAS_I2)
		nvlist_add_binary(nvl_device, "i2", dev->i2, strlen(dev->i2) + 1);
	if (dev->flags & WGDEVICE_HAS_I3)
		nvlist_add_binary(nvl_device, "i3", dev->i3, strlen(dev->i3) + 1);
	if (dev->flags & WGDEVICE_HAS_I4)
		nvlist_add_binary(nvl_device, "i4", dev->i4, strlen(dev->i4) + 1);
	if (dev->flags & WGDEVICE_HAS_I5)
		nvlist_add_binary(nvl_device, "i5", dev->i5, strlen(dev->i5) + 1);
	if (dev->flags & WGDEVICE_HAS_HEADER_PROTECTION_KEY)
		nvlist_add_binary(nvl_device, "header-protection-key", dev->header_protection_key,
			sizeof(dev->header_protection_key));
	if (dev->flags & WGDEVICE_HAS_CONTENT_PADDING_ADDITION)
		nvlist_add_number(nvl_device, "content-padding-addition", dev->content_padding_addition);
	if (dev->flags & WGDEVICE_HAS_REKEY_AFTER_TIME)
		nvlist_add_number(nvl_device, "rekey-after-time", dev->rekey_after_time);
	if (dev->flags & WGDEVICE_HAS_REKEY_TIMEOUT)
		nvlist_add_number(nvl_device, "rekey-timeout", dev->rekey_timeout);
	if (dev->flags & WGDEVICE_HAS_REJECT_AFTER_TIME)
		nvlist_add_number(nvl_device, "reject-after-time", dev->reject_after_time);
	if (dev->flags & WGDEVICE_HAS_KEEPALIVE_TIMEOUT)
		nvlist_add_number(nvl_device, "keepalive-timeout", dev->keepalive_timeout);
	if (dev->flags & WGDEVICE_HAS_MAX_HANDSHAKE_ATTEMPTS)
		nvlist_add_number(nvl_device, "max-handshake-attempts", dev->max_handshake_attempts);
	if (dev->flags & WGDEVICE_HAS_RANDOM_TRAILERS)
		nvlist_add_bool(nvl_device, "random-trailers", dev->random_trailers);
	if (dev->flags & WGDEVICE_HAS_DISABLE_COOKIES)
		nvlist_add_bool(nvl_device, "disable-cookies", dev->disable_cookies);
	if (dev->flags & WGDEVICE_HAS_FWMARK)
		nvlist_add_number(nvl_device, "user-cookie", dev->fwmark);
	if (dev->flags & WGDEVICE_REPLACE_PEERS)
		nvlist_add_bool(nvl_device, "replace-peers", true);

	for_each_wgpeer(dev, peer) {
		size_t aip_count = 0, j = 0;
		nvlist_t **nvl_aips = NULL;
		struct wgallowedip *aip;

		nvl_peers[i]  = nvlist_create(0);
		if (!nvl_peers[i])
			goto err_peer;
		for_each_wgallowedip(peer, aip)
			++aip_count;
		if (aip_count) {
			nvl_aips = calloc(aip_count, sizeof(*nvl_aips));
			if (!nvl_aips)
				goto err_peer;
		}
		nvlist_add_binary(nvl_peers[i], "public-key", peer->public_key, sizeof(peer->public_key));
		if (peer->flags & WGPEER_HAS_PRESHARED_KEY)
			nvlist_add_binary(nvl_peers[i], "preshared-key", peer->preshared_key, sizeof(peer->preshared_key));
		if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL)
			nvlist_add_number(nvl_peers[i], "persistent-keepalive-interval",
				version >= WG_AWG_VERSION_3 ? peer->persistent_keepalive_interval :
				u16_range_lo(peer->persistent_keepalive_interval));
		if (peer->endpoint.addr.sa_family == AF_INET || peer->endpoint.addr.sa_family == AF_INET6)
			nvlist_add_binary(nvl_peers[i], "endpoint", &peer->endpoint.addr, peer->endpoint.addr.sa_len);
		if (peer->flags & WGPEER_REPLACE_ALLOWEDIPS)
			nvlist_add_bool(nvl_peers[i], "replace-allowedips", true);
		if (peer->flags & WGPEER_REMOVE_ME)
			nvlist_add_bool(nvl_peers[i], "remove", true);
		for_each_wgallowedip(peer, aip) {
			nvl_aips[j] = nvlist_create(0);
			if (!nvl_aips[j])
				goto err_peer;
			if (aip->flags)
				nvlist_add_number(nvl_aips[j], "flags", aip->flags);
			nvlist_add_number(nvl_aips[j], "cidr", aip->cidr);
			if (aip->family == AF_INET)
				nvlist_add_binary(nvl_aips[j], "ipv4", &aip->ip4, sizeof(aip->ip4));
			else if (aip->family == AF_INET6)
				nvlist_add_binary(nvl_aips[j], "ipv6", &aip->ip6, sizeof(aip->ip6));
			++j;
		}
		if (j) {
			nvlist_add_nvlist_array(nvl_peers[i], "allowed-ips", (const nvlist_t *const *)nvl_aips, j);
			for (j = 0; j < aip_count; ++j)
				nvlist_destroy(nvl_aips[j]);
			free(nvl_aips);
		}
		++i;
		continue;

	err_peer:
		ret = -errno;
		for (j = 0; j < aip_count && nvl_aips; ++j)
			nvlist_destroy(nvl_aips[j]);
		free(nvl_aips);
		nvlist_destroy(nvl_peers[i]);
		nvl_peers[i] = NULL;
		goto err;
	}
	if (i) {
		nvlist_add_nvlist_array(nvl_device, "peers", (const nvlist_t *const *)nvl_peers, i);
		for (i = 0; i < peer_count; ++i)
			nvlist_destroy(nvl_peers[i]);
		free(nvl_peers);
		nvl_peers = NULL;
	}
	wgd.wgd_data = nvlist_pack(nvl_device, &wgd.wgd_size);
	nvlist_destroy(nvl_device);
	nvl_device = NULL;
	if (!wgd.wgd_data)
		goto err;
	s = get_dgram_socket();
	if (s < 0)
		return -errno;
	return ioctl(s, SIOCSWG, &wgd);

err:
	if (!ret)
		ret = -errno;
	for (i = 0; i < peer_count && nvl_peers; ++i)
		nvlist_destroy(nvl_peers[i]);
	free(nvl_peers);
	nvlist_destroy(nvl_device);
	return ret;
}
