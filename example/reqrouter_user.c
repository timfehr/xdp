// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2018 Intel Corporation. */
/* Extended by Marius Gerling 2018 */

#include <stdio.h>
#include <string.h>
#include <string.h>
#include <signal.h>
#include <locale.h>
#include <libxdp.h>
#include "functions.h"

static u32 opt_xdp_flags;
static const char *opt_if = "";
static int opt_ifindex;
static int opt_poll;
static int opt_threads = 1;
static u32 opt_xdp_bind_flags;
static int opt_port = 8883;
unsigned h_length = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);

static struct option long_options[] = {
        {"interface",  required_argument, 0, 'i'},
        {"port",       required_argument, 0, 'P'},
        {"queues",     required_argument, 0, 'q'},
        {"poll",       no_argument,       0, 'p'},
        {"xdp-skb",    no_argument,       0, 'S'},
        {"xdp-native", no_argument,       0, 'N'},
        {"threads",    required_argument, 0, 't'},
        {0,            0,                 0, 0}
};

static void usage(const char *prog) {
    const char *str =
            "  Usage: %s [OPTIONS]\n"
            "  Options:\n"
            "  -i, --interface=n	Run on interface n\n"
            "  -P, --port=n         Port to listen (default 8883)"
            "  -q, --queues=n	    Number of queues (defaults to 1)\n"
            "  -p, --poll		    Use poll syscall\n"
            "  -S, --xdp-skb=n	    Use XDP skb-mod\n"
            "  -N, --xdp-native=n	Enfore XDP native mode\n"
            "  -t, --threads=n	    Specify worker threads (default to 1).\n"
            "\n";
    fprintf(stderr, str, prog);
    exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv) {
    int option_index, c;

    opterr = 0;

    for (;;) {
        c = getopt_long(argc, argv, "i:P:q:pSNt:", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'i':
                opt_if = optarg;
                break;
            case 'P':
                opt_port = atoi(optarg);
                break;
            case 'q':
                opt_queues = atoi(optarg);
                break;
            case 'p':
                opt_poll = 1;
                break;
            case 'S':
                opt_xdp_flags |= XDP_FLAGS_SKB_MODE;
                opt_xdp_bind_flags |= XDP_COPY;
                break;
            case 'N':
                opt_xdp_flags |= XDP_FLAGS_DRV_MODE;
                break;
            case 't':
                opt_threads = atoi(optarg);
                break;
            default:
                usage(basename(argv[0]));
        }
    }

    opt_ifindex = if_nametoindex(opt_if);
    if (!opt_ifindex) {
        fprintf(stderr, "ERROR: interface \"%s\" does not exist\n",
                opt_if);
        usage(basename(argv[0]));
    }
}

int main(int argc, char **argv) {
    parse_command_line(argc, argv);

    set_options(opt_xdp_flags, opt_ifindex, opt_xdp_bind_flags);

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_prog_load_attr prog_load_attr = {
            .prog_type    = BPF_PROG_TYPE_XDP,
    };
    int prog_fd, xsks_map, rr_map, num_socks_map, num_queues_map;
    struct bpf_object *obj;
    char xdp_filename[256];
    struct bpf_map *map;
    int q, pqt, key = 0, ret;
    int port = opt_port;
    struct sock_port *sp = NULL;
    int timeout = 1000; ret = 0;
    unsigned int rcvd, i, l;
    char *pkt = NULL;
    struct xdp_desc descs[BATCH_SIZE];

    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    snprintf(xdp_filename, sizeof(xdp_filename), "%s_kern.o", argv[0]);
    prog_load_attr.file = xdp_filename;

    if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
        exit(EXIT_FAILURE);
    if (prog_fd < 0) {
        fprintf(stderr, "ERROR: no program found: %s\n",
                strerror(prog_fd));
        exit(EXIT_FAILURE);
    }

    map = bpf_object__find_map_by_name(obj, "xsks_map");
    xsks_map = bpf_map__fd(map);
    if (xsks_map < 0) {
        fprintf(stderr, "ERROR: no xsks map found: %s\n",
                strerror(xsks_map));
        exit(EXIT_FAILURE);
    }

    map = bpf_object__find_map_by_name(obj, "num_socks_map");
    num_socks_map = bpf_map__fd(map);
    if (num_socks_map < 0) {
        fprintf(stderr, "ERROR: no num_socks map found: %s\n",
                strerror(num_socks_map));
        exit(EXIT_FAILURE);
    }

    map = bpf_object__find_map_by_name(obj, "rr_map");
    rr_map = bpf_map__fd(map);
    if (rr_map < 0) {
        fprintf(stderr, "ERROR: no rr map found: %s\n",
                strerror(rr_map));
        exit(EXIT_FAILURE);
    }

    map = bpf_object__find_map_by_name(obj, "num_queues_map");
    num_queues_map = bpf_map__fd(map);
    if (rr_map < 0) {
        fprintf(stderr, "ERROR: no rr map found: %s\n",
                strerror(num_queues_map));
        exit(EXIT_FAILURE);
    }

    if (bpf_set_link_xdp_fd(opt_ifindex, prog_fd, opt_xdp_flags) < 0) {
        fprintf(stderr, "ERROR: link set xdp fd failed\n");
        exit(EXIT_FAILURE);
    }
    fprintf(stdout, "Let's create Sockets!\n");

    /* Create sockets... */

    for (q = 0; q < opt_queues; q++) { // q -> queue
        pqt = create_socket(port, q, 0);
        if (pqt < 0) {
            fprintf(stderr,
                    "ERROR: Socket creation failed\n");
            exit(EXIT_FAILURE);
        }
        ret = bpf_map_update_elem(xsks_map, &pqt, &xsks[pqt]->sfd, 0);
        if (ret) {
            fprintf(stderr, "Error: bpf_map_update_elem %d\n", pqt);
            fprintf(stderr, "ERRNO: %d\n", errno);
            fprintf(stderr, "%s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        // Configure and start the consumer thread
        sp = malloc(sizeof(struct sock_port));
        (*sp).length = 1;
        (*sp).xsks = malloc(sizeof(struct xdpsock *) * (*sp).length);
        (*sp).xsks[0] = xsks[pqt];
        (*sp).ports = malloc(sizeof(int) * (*sp).length);
        (*sp).ports[0] = port;
        (*sp).id = pqt;

        // Set the number of threads per queue
        ret = bpf_map_update_elem(num_socks_map, &pqt, &opt_threads, 0);
        if (ret) {
            fprintf(stderr, "Error: bpf_map_update_elem %d\n", pqt);
            fprintf(stderr, "ERRNO: %d\n", errno);
            fprintf(stderr, "%s", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    fprintf(stdout, "Listen now on Port %d\n", port);

    // Set the number of queues
    ret = bpf_map_update_elem(num_queues_map, &key, &opt_queues, 0);
    if (ret) {
        fprintf(stderr, "Error: bpf_map_update_elem\n");
        fprintf(stderr, "ERRNO: %d\n", errno);
        fprintf(stderr, "%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);
    signal(SIGABRT, int_exit);

    setlocale(LC_ALL, "");

    function func[sp->length];
    struct pollfd pfd[sp->length];
    memset(&pfd, 0, sizeof(pfd));
    for (l = 0; l < sp->length; l++) {
        func[l] = get_function(sp->ports[l]);
        if (func == NULL) {
            printf("No function defined!\n");
            exit(-1);
        }
        pfd[l].fd = sp->xsks[l]->sfd;
        pfd[l].events = POLLIN;
    }

    FILE *fp;
    fp = fopen("traffic.dump", "w");
    if (fp == NULL) {
        printf("Could not open file to dump the traffic \n");
    }

    for (;;) {
        if (opt_poll) { // Poll new data
            ret = poll(pfd, sp->length, timeout);
            if (ret <= 0) {
                fprintf(stdout, "Timeout(%d)\n", sp->id);
                fflush(stdout);
                continue;
            }
        }

        for (l = 0; l < sp->length; l++) {
            if (opt_poll && pfd[l].revents == 0)
                continue;
            rcvd = xq_deq(&sp->xsks[l]->rx, descs, BATCH_SIZE);
            if (rcvd == 0)
                continue;

            // Execute the function for every packet
            for (i = 0; i < rcvd; i++) {
                pkt = xq_get_data(sp->xsks[l], descs[i].addr);

                //fprintf(stdout, "Port %d: ", sp->ports[l]);
                hexDump(NULL, pkt, descs[i].len, fp);
                fflush(stdout);

                // Swap ETH, IP and UDP header
                if (!swap_header(pkt, descs[i].len)) {
                    fprintf(stderr, "Port %d: Header to short\n", sp->ports[l]);
                    continue;
                }

                printf("Payload an Port %d: ", sp->ports[l]);

                if (!(*func[l])(pkt, &descs[i].len, h_length)) {
                    fprintf(stderr, "Port %d: Function failed\n", sp->ports[l]);
                    continue;
                } // Todo: Calculate checksum if length changed

                printf("\n");

                hexDump(NULL, pkt, descs[i].len, fp);
                fflush(stdout);
            }

            send_packet(sp, descs, rcvd, l);
        }
    }

    fclose(fp);
    free(sp->xsks);
    free(sp->ports);
    free(sp);

    return 0;
}
