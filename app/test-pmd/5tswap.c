/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2014-2020 Mellanox Technologies, Ltd
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_flow.h>

#include "testpmd.h"


static inline void
swap_mac(struct rte_ether_hdr *eth_hdr)
{
	struct rte_ether_addr addr;

	/* Swap dest and src mac addresses. */
	rte_ether_addr_copy(&eth_hdr->dst_addr, &addr);
	rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
	rte_ether_addr_copy(&addr, &eth_hdr->src_addr);
}

static inline void
swap_ipv4(struct rte_ipv4_hdr *ipv4_hdr)
{
	rte_be32_t addr;

	/* Swap dest and src ipv4 addresses. */
	addr = ipv4_hdr->src_addr;
	ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
	ipv4_hdr->dst_addr = addr;
}

static inline void
swap_ipv6(struct rte_ipv6_hdr *ipv6_hdr)
{
	uint8_t addr[16];

	/* Swap dest and src ipv6 addresses. */
	memcpy(&addr, &ipv6_hdr->src_addr, 16);
	memcpy(&ipv6_hdr->src_addr, &ipv6_hdr->dst_addr, 16);
	memcpy(&ipv6_hdr->dst_addr, &addr, 16);
}

static inline void
swap_tcp(struct rte_tcp_hdr *tcp_hdr)
{
	rte_be16_t port;

	/* Swap dest and src tcp port. */
	port = tcp_hdr->src_port;
	tcp_hdr->src_port = tcp_hdr->dst_port;
	tcp_hdr->dst_port = port;
}

static inline void
swap_udp(struct rte_udp_hdr *udp_hdr)
{
	rte_be16_t port;

	/* Swap dest and src udp port */
	port = udp_hdr->src_port;
	udp_hdr->src_port = udp_hdr->dst_port;
	udp_hdr->dst_port = port;
}
