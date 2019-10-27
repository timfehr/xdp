// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2018 Intel Corporation. */
/* Extended by Marius Gerling 2018 */

#ifndef REQROUTER_C
#define REQROUTER_C

#include "reqrouter.h"

unsigned header_length = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);

void set_options(int flags, int index, int bindflags) {
    opt_xdp_bind_flags = bindflags;
    opt_ifindex = index;
    opt_xdp_flags = flags;
}

u32 umem_nb_free(struct xdp_umem_uqueue *q, u32 nb) {
    u32 free_entries = q->cached_cons - q->cached_prod;

    if (free_entries >= nb)
        return free_entries;

    /* Refresh the local tail pointer */
    q->cached_cons = *q->consumer + q->size;

    return q->cached_cons - q->cached_prod;
}

u32 xq_nb_free(struct xdp_uqueue *q, u32 ndescs) {
    u32 free_entries = q->cached_cons - q->cached_prod;

    if (free_entries >= ndescs)
        return free_entries;

    /* Refresh the local tail pointer */
    q->cached_cons = *q->consumer + q->size;
    return q->cached_cons - q->cached_prod;
}

u32 umem_nb_avail(struct xdp_umem_uqueue *q, u32 nb) {
    u32 entries = q->cached_prod - q->cached_cons;

    if (entries == 0) {
        q->cached_prod = *q->producer;
        entries = q->cached_prod - q->cached_cons;
    }

    return (entries > nb) ? nb : entries;
}

u32 xq_nb_avail(struct xdp_uqueue *q, u32 ndescs) {
    u32 entries = q->cached_prod - q->cached_cons;

    if (entries == 0) {
        q->cached_prod = *q->producer;
        entries = q->cached_prod - q->cached_cons;
    }

    return (entries > ndescs) ? ndescs : entries;
}

int umem_fill_to_kernel(struct xdp_umem_uqueue *fq, u64 *d,
                                      size_t nb) {
    u32 i;

    if (umem_nb_free(fq, nb) < nb)
        return -ENOSPC;

    for (i = 0; i < nb; i++) {
        u32 idx = fq->cached_prod++ & fq->mask;

        fq->ring[idx] = d[i];
    }

    u_smp_wmb();

    *fq->producer = fq->cached_prod;

    return 0;
}

size_t umem_complete_from_kernel(struct xdp_umem_uqueue *cq,
                                               u64 *d, size_t nb) {
    u32 idx, i, entries = umem_nb_avail(cq, nb);

    u_smp_rmb();

    for (i = 0; i < entries; i++) {
        idx = cq->cached_cons++ & cq->mask;
        d[i] = cq->ring[idx];
    }

    if (entries > 0) {
        u_smp_wmb();

        *cq->consumer = cq->cached_cons;
    }

    return entries;
}

void *xq_get_data(struct xdpsock *xsk, u64 addr) {
    return &xsk->umem->frames[addr];
}

int xq_enq(struct xdp_uqueue *uq,
                         const struct xdp_desc *descs,
                         unsigned int ndescs) {
    struct xdp_desc *r = uq->ring;
    unsigned int i;

    if (xq_nb_free(uq, ndescs) < ndescs)
        return -ENOSPC;

    for (i = 0; i < ndescs; i++) {
        u32 idx = uq->cached_prod++ & uq->mask;

        r[idx].addr = descs[i].addr;
        r[idx].len = descs[i].len;
    }

    u_smp_wmb();

    *uq->producer = uq->cached_prod;
    return 0;
}

int xq_deq(struct xdp_uqueue *uq,
                         struct xdp_desc *descs,
                         int ndescs) {
    struct xdp_desc *r = uq->ring;
    unsigned int idx;
    int i, entries;

    entries = xq_nb_avail(uq, ndescs);

    u_smp_rmb();

    for (i = 0; i < entries; i++) {
        idx = uq->cached_cons++ & uq->mask;
        descs[i] = r[idx];
    }

    if (entries > 0) {
        u_smp_wmb();

        *uq->consumer = uq->cached_cons;
    }

    return entries;
}

bool swap_header(void *data, u64 l) {
    if (l < header_length) {
        return false;
    }
    //Eth-Header (MAC Adresses)
    struct ether_header *eth = (struct ether_header *) data;
    struct ether_addr *src_addr = (struct ether_addr *) &eth->ether_shost;
    struct ether_addr *dst_addr = (struct ether_addr *) &eth->ether_dhost;
    struct ether_addr eth_tmp;

    eth_tmp = *src_addr;
    *src_addr = *dst_addr;
    *dst_addr = eth_tmp;

    u64 offset = sizeof(*eth);

    //IP-Header (IP-Adresses)
    struct iphdr *iph = (struct iphdr *) (data + offset);
    u32 ip_tmp = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = ip_tmp;
    //Checksum stays the same. Change of length requires recalculation
    offset += sizeof(*iph);

    //UDP-Header (Ports)
    struct udphdr *udph = (struct udphdr *) (data + offset);
    u16 udp_tmp = udph->source;
    udph->source = udph->dest;
    udph->dest = udp_tmp;
    //Clear the checksum
    udph->check = 0;

    return true;
}

struct xdp_umem *xdp_umem_configure(int sfd) {
    int fq_size = FQ_NUM_DESCS, cq_size = CQ_NUM_DESCS;
    struct xdp_mmap_offsets off;
    struct xdp_umem_reg mr;
    struct xdp_umem *umem;
    socklen_t optlen;
    void *bufs;

    umem = calloc(1, sizeof(*umem));
    lassert(umem);

    lassert(posix_memalign(&bufs, getpagesize(), /* PAGE_SIZE aligned */
                           NUM_FRAMES * FRAME_SIZE) == 0);

    mr.addr = (__u64) bufs;
    mr.len = NUM_FRAMES * FRAME_SIZE;
    mr.chunk_size = FRAME_SIZE;
    mr.headroom = FRAME_HEADROOM;

    lassert(setsockopt(sfd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) == 0);
    lassert(setsockopt(sfd, SOL_XDP, XDP_UMEM_FILL_RING, &fq_size,
                       sizeof(int)) == 0);
    lassert(setsockopt(sfd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &cq_size,
                       sizeof(int)) == 0);

    optlen = sizeof(off);
    lassert(getsockopt(sfd, SOL_XDP, XDP_MMAP_OFFSETS, &off,
                       &optlen) == 0);

    umem->fq.map = mmap(0, off.fr.desc +
                           FQ_NUM_DESCS * sizeof(u64),
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, sfd,
                        XDP_UMEM_PGOFF_FILL_RING);
    lassert(umem->fq.map != MAP_FAILED);

    umem->fq.mask = FQ_NUM_DESCS - 1;
    umem->fq.size = FQ_NUM_DESCS;
    umem->fq.producer = umem->fq.map + off.fr.producer;
    umem->fq.consumer = umem->fq.map + off.fr.consumer;
    umem->fq.ring = umem->fq.map + off.fr.desc;
    umem->fq.cached_cons = FQ_NUM_DESCS;

    umem->cq.map = mmap(0, off.cr.desc +
                           CQ_NUM_DESCS * sizeof(u64),
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, sfd,
                        XDP_UMEM_PGOFF_COMPLETION_RING);
    lassert(umem->cq.map != MAP_FAILED);

    umem->cq.mask = CQ_NUM_DESCS - 1;
    umem->cq.size = CQ_NUM_DESCS;
    umem->cq.producer = umem->cq.map + off.cr.producer;
    umem->cq.consumer = umem->cq.map + off.cr.consumer;
    umem->cq.ring = umem->cq.map + off.cr.desc;

    umem->frames = bufs;
    umem->fd = sfd;

    return umem;
}

struct xdpsock *xsk_configure(struct xdp_umem *umem, int queue) {
    struct sockaddr_xdp sxdp = {};
    struct xdp_mmap_offsets off;
    int sfd, ndescs = NUM_DESCS;
    struct xdpsock *xsk;
    bool shared = true;
    socklen_t optlen;
    u64 i;

    sfd = socket(PF_XDP, SOCK_RAW, 0);
    lassert(sfd >= 0);

    xsk = calloc(1, sizeof(*xsk));
    lassert(xsk);

    xsk->sfd = sfd;
    xsk->outstanding_tx = 0;

    if (!umem) {
        shared = false;
        xsk->umem = xdp_umem_configure(sfd);
    } else {
        xsk->umem = umem;
    }

    lassert(setsockopt(sfd, SOL_XDP, XDP_RX_RING,
                       &ndescs, sizeof(int)) == 0);
    lassert(setsockopt(sfd, SOL_XDP, XDP_TX_RING,
                       &ndescs, sizeof(int)) == 0);
    optlen = sizeof(off);
    lassert(getsockopt(sfd, SOL_XDP, XDP_MMAP_OFFSETS, &off,
                       &optlen) == 0);

    /* Rx */
    xsk->rx.map = mmap(NULL,
                       off.rx.desc +
                       NUM_DESCS * sizeof(struct xdp_desc),
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, sfd,
                       XDP_PGOFF_RX_RING);
    lassert(xsk->rx.map != MAP_FAILED);

    if (!shared) {
        for (i = 0; i < NUM_DESCS * FRAME_SIZE; i += FRAME_SIZE)
            lassert(umem_fill_to_kernel(&xsk->umem->fq, &i, 1)
                    == 0);
    }

    /* Tx */
    xsk->tx.map = mmap(NULL,
                       off.tx.desc +
                       NUM_DESCS * sizeof(struct xdp_desc),
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, sfd,
                       XDP_PGOFF_TX_RING);
    lassert(xsk->tx.map != MAP_FAILED);

    xsk->rx.mask = NUM_DESCS - 1;
    xsk->rx.size = NUM_DESCS;
    xsk->rx.producer = xsk->rx.map + off.rx.producer;
    xsk->rx.consumer = xsk->rx.map + off.rx.consumer;
    xsk->rx.ring = xsk->rx.map + off.rx.desc;

    xsk->tx.mask = NUM_DESCS - 1;
    xsk->tx.size = NUM_DESCS;
    xsk->tx.producer = xsk->tx.map + off.tx.producer;
    xsk->tx.consumer = xsk->tx.map + off.tx.consumer;
    xsk->tx.ring = xsk->tx.map + off.tx.desc;
    xsk->tx.cached_cons = NUM_DESCS;

    sxdp.sxdp_family = PF_XDP;
    sxdp.sxdp_ifindex = opt_ifindex;
    sxdp.sxdp_queue_id = queue;

    if (shared) {
        sxdp.sxdp_flags = XDP_SHARED_UMEM;
        sxdp.sxdp_shared_umem_fd = umem->fd;
    } else {
        sxdp.sxdp_flags = opt_xdp_bind_flags;
    }

    lassert(bind(sfd, (struct sockaddr *) &sxdp, sizeof(sxdp)) == 0);

    return xsk;
}

void int_exit(int sig) {
    (void) sig;
    bpf_set_link_xdp_fd(opt_ifindex, -1, opt_xdp_flags);
    exit(EXIT_SUCCESS);
}

void kick_tx(int fd) {
    int ret;

    ret = sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY)
        return;
    lassert(0);
}

void complete_tx(struct xdpsock *xsk) {
    u64 descs[BATCH_SIZE];
    unsigned int rcvd;
    size_t ndescs;

    if (!xsk->outstanding_tx)
        return;

    kick_tx(xsk->sfd);
    ndescs = (xsk->outstanding_tx > BATCH_SIZE) ? BATCH_SIZE :
             xsk->outstanding_tx;

    // re-add completed Tx buffers
    rcvd = umem_complete_from_kernel(&xsk->umem->cq, descs, ndescs);
    if (rcvd > 0) {
        umem_fill_to_kernel(&xsk->umem->fq, descs, rcvd);
        xsk->outstanding_tx -= rcvd;
    }
}

int create_socket(int port, int queue, int thread) {
    int offset = MAX_SOCKS / opt_queues;
    offset = offset * queue;
    offset = offset + thread;
    offset = offset + port;

    printf("Port: %d, Queue; %d, Thread: %d, Offset: %d\n", port, queue, thread, offset);
    // Check if offset is valid
    if (offset > PORT_RANGE_UPPER || offset < PORT_RANGE_LOWER || offset >= port + MAX_SOCKS)
        return -1;
    // Create socket at queue
    //printf("If Bedingung wurde auch ausgeführt\n");
    xsks[offset] = xsk_configure(NULL, queue);
    return offset;
}

void hexDump(const char *desc, const void *addr, const int len, FILE *fp) {
    int i;
    unsigned char buff[17];
    const unsigned char *pc = (const unsigned char *) addr;

    // Output description if given.
    if (desc != NULL)
        printf("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n", len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                fprintf(fp, "  %s\n", buff);

            // Output the offset.
            fprintf(fp, "  %04x ", i);
        }

        // Now the hex code for the specific character.
        fprintf(fp, " %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        fprintf(fp, "   ");
        i++;
    }

    // And print the final ASCII bit.
    fprintf(fp, "  %s\n", buff);
}

int send_packet(void *arg, const struct xdp_desc *descs, unsigned int rcvd, int l) {
    struct sock_port *sp = (struct sock_port *) arg;

    // Back to the Kernel by TX
    int ret = xq_enq(&sp->xsks[l]->tx, descs, rcvd);
    lassert(ret == 0);
    sp->xsks[l]->outstanding_tx += rcvd;
    // Complete the TX
    complete_tx(sp->xsks[l]);

    return 0;
}

#endif