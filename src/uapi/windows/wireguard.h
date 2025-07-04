/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2021 WireGuard LLC. All Rights Reserved.
 */

#ifndef _WIREGUARD_NT_H
#define _WIREGUARD_NT_H

#include <ntdef.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <inaddr.h>
#include <in6addr.h>

#define WG_KEY_LEN 32

typedef struct _WG_IOCTL_ALLOWED_IP
{
	union
	{
		IN_ADDR V4;
		IN6_ADDR V6;
	} Address;
		ADDRESS_FAMILY AddressFamily;
		UCHAR Cidr;
} __attribute__((aligned(8))) WG_IOCTL_ALLOWED_IP;

typedef enum
{
	WG_IOCTL_PEER_HAS_PUBLIC_KEY = 1 << 0,
	WG_IOCTL_PEER_HAS_PRESHARED_KEY = 1 << 1,
	WG_IOCTL_PEER_HAS_PERSISTENT_KEEPALIVE = 1 << 2,
	WG_IOCTL_PEER_HAS_ENDPOINT = 1 << 3,
	WG_IOCTL_PEER_HAS_PROTOCOL_VERSION = 1 << 4,
	WG_IOCTL_PEER_REPLACE_ALLOWED_IPS = 1 << 5,
	WG_IOCTL_PEER_REMOVE = 1 << 6,
	WG_IOCTL_PEER_UPDATE = 1 << 7
} WG_IOCTL_PEER_FLAG;

typedef struct _WG_IOCTL_PEER
{
	WG_IOCTL_PEER_FLAG Flags;
	ULONG ProtocolVersion; /* 0 = latest protocol, 1 = this protocol. */
	UCHAR PublicKey[WG_KEY_LEN];
	UCHAR PresharedKey[WG_KEY_LEN];
	USHORT PersistentKeepalive;
	SOCKADDR_INET Endpoint;
	ULONG64 TxBytes;
	ULONG64 RxBytes;
	ULONG64 LastHandshake;
	ULONG AllowedIPsCount;
} __attribute__((aligned(8))) WG_IOCTL_PEER;

typedef enum
{
	WG_IOCTL_INTERFACE_HAS_PUBLIC_KEY = 1 << 0,
	WG_IOCTL_INTERFACE_HAS_PRIVATE_KEY = 1 << 1,
	WG_IOCTL_INTERFACE_HAS_LISTEN_PORT = 1 << 2,
	WG_IOCTL_INTERFACE_REPLACE_PEERS = 1 << 3,
	WG_IOCTL_INTERFACE_PEERS = 1 << 4,
	WG_IOCTL_INTERFACE_JC = 1 << 5,
	WG_IOCTL_INTERFACE_JMIN = 1 << 6,
	WG_IOCTL_INTERFACE_JMAX = 1 << 7,
	WG_IOCTL_INTERFACE_S1 = 1 << 8,
	WG_IOCTL_INTERFACE_S2 = 1 << 9,
	WG_IOCTL_INTERFACE_S3 = 1 << 10,
	WG_IOCTL_INTERFACE_S4 = 1 << 11,
	WG_IOCTL_INTERFACE_H1 = 1 << 12,
	WG_IOCTL_INTERFACE_H2 = 1 << 12,
	WG_IOCTL_INTERFACE_H3 = 1 << 13,
	WG_IOCTL_INTERFACE_H4 = 1 << 14,
	WG_IOCTL_INTERFACE_I1 = 1U << 15,
	WG_IOCTL_INTERFACE_I2 = 1U << 16,
	WG_IOCTL_INTERFACE_I3 = 1U << 17,
	WG_IOCTL_INTERFACE_I4 = 1U << 18,
	WG_IOCTL_INTERFACE_I5 = 1U << 19,
	WG_IOCTL_INTERFACE_J1 = 1U << 20,
	WG_IOCTL_INTERFACE_J2 = 1U << 21,
	WG_IOCTL_INTERFACE_J3 = 1U << 22,
	WG_IOCTL_INTERFACE_ITIME = 1U << 23
} WG_IOCTL_INTERFACE_FLAG;

typedef struct _WG_IOCTL_INTERFACE
{
	WG_IOCTL_INTERFACE_FLAG Flags;
	USHORT ListenPort;
	UCHAR PrivateKey[WG_KEY_LEN];
	UCHAR PublicKey[WG_KEY_LEN];
	ULONG PeersCount;
	USHORT JunkPacketCount;
	USHORT JunkPacketMinSize;
	USHORT JunkPacketMaxSize;
	USHORT InitPacketJunkSize;
	USHORT ResponsePacketJunkSize;
	USHORT CookieReplyPacketJunkSize;
	USHORT TransportPacketJunkSize;
	ULONG InitPacketMagicHeader;
	ULONG ResponsePacketMagicHeader;
	ULONG UnderloadPacketMagicHeader;
	ULONG TransportPacketMagicHeader;

	UCHAR* I1;
	UCHAR* I2;
	UCHAR* I3;
	UCHAR* I4;
	UCHAR* I5;
	UCHAR* J1;
	UCHAR* J2;
	UCHAR* J3;
	ULONG  Itime;
} __attribute__((aligned(8))) WG_IOCTL_INTERFACE;

#define WG_IOCTL_GET CTL_CODE(45208U, 321, METHOD_OUT_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
#define WG_IOCTL_SET CTL_CODE(45208U, 322, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)

#define DEVPKEY_WG_NAME (DEVPROPKEY) { \
		{ 0x65726957, 0x7547, 0x7261, { 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x4b, 0x65, 0x79 } }, \
		DEVPROPID_FIRST_USABLE + 1 \
	}


#endif
