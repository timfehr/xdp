/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDPSOCK_H_
#define XDPSOCK_H_

#pragma once

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <sys/types.h>
#include <poll.h>

#include <bpf/libbpf.h>
#include "bpf_util.h"
#include <bpf/bpf.h>

#include <linux/ip.h>
#include <linux/udp.h>

/* Power-of-2 number of sockets per function */
#define MAX_SOCKS 1

/* Port Range for the requestrouter */
#define PORT_RANGE_LOWER 1200
#define PORT_RANGE_UPPER 16000

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define NUM_FRAMES 131072
#define FRAME_HEADROOM 0
#define FRAME_SIZE 2048
#define NUM_DESCS 1024
#define BATCH_SIZE 16

#define FQ_NUM_DESCS 1024
#define CQ_NUM_DESCS 1024

#define DEBUG_HEXDUMP 0

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;

static u32 opt_xdp_flags;
static int opt_ifindex;
static int opt_queues = 1;
static u32 opt_xdp_bind_flags;

struct xdp_umem_uqueue {
    u32 cached_prod;
    u32 cached_cons;
    u32 mask;
    u32 size;
    u32 *producer;
    u32 *consumer;
    u64 *ring;
    void *map;
};

struct xdp_umem {
    char *frames;
    struct xdp_umem_uqueue fq;
    struct xdp_umem_uqueue cq;
    int fd;
};

struct xdp_uqueue {
    u32 cached_prod;
    u32 cached_cons;
    u32 mask;
    u32 size;
    u32 *producer;
    u32 *consumer;
    struct xdp_desc *ring;
    void *map;
};

struct xdpsock {
    struct xdp_uqueue rx;
    struct xdp_uqueue tx;
    int sfd;
    struct xdp_umem *umem;
    u32 outstanding_tx;
};

struct xdpsock *xsks[PORT_RANGE_UPPER];

struct sock_port {
    struct xdpsock **xsks;
    int *ports;
    int length;
    int id;
};

#define lassert(expr)                            \
    do {                                \
        if (!(expr)) {                        \
            fprintf(stderr, "%s:%s:%i: Assertion failed: "    \
                #expr ": errno: %d/\"%s\"\n",        \
                __FILE__, __func__, __LINE__,        \
                errno, strerror(errno));        \
            exit(EXIT_FAILURE);                \
        }                            \
    } while (0)

#define barrier() __asm__ __volatile__("": : :"memory")
#ifdef __aarch64__
#define u_smp_rmb() __asm__ __volatile__("dmb ishld": : :"memory")
#define u_smp_wmb() __asm__ __volatile__("dmb ishst": : :"memory")
#else
#define u_smp_rmb() barrier()
#define u_smp_wmb() barrier()
#endif
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

void set_options(int flags, int index, int bindflags);

u32 umem_nb_free(struct xdp_umem_uqueue *q, u32 nb);

u32 xq_nb_free(struct xdp_uqueue *q, u32 ndescs);

u32 umem_nb_avail(struct xdp_umem_uqueue *q, u32 nb);

u32 xq_nb_avail(struct xdp_uqueue *q, u32 ndescs);

int umem_fill_to_kernel(struct xdp_umem_uqueue *fq, u64 *d, size_t nb);

size_t umem_complete_from_kernel(struct xdp_umem_uqueue *cq, u64 *d, size_t nb);

void *xq_get_data(struct xdpsock *xsk, u64 addr);

int xq_enq(struct xdp_uqueue *uq, const struct xdp_desc *descs, unsigned int ndescs);

int xq_deq(struct xdp_uqueue *uq, struct xdp_desc *descs, int ndescs);

bool swap_header(void *data, u64 l);

struct xdp_umem *xdp_umem_configure(int sfd);

struct xdpsock *xsk_configure(struct xdp_umem *umem, int queue);

void int_exit(int sig);

void kick_tx(int fd);

void complete_tx(struct xdpsock *xsk);

int create_socket(int port, int queue, int thread);

void hexDump(const char *desc, const void *addr, const int len, FILE *fp);

int send_packet(void *arg, const struct xdp_desc *descs, unsigned int rcvd, int l);

#endif /* XDPSOCK_H_ */
