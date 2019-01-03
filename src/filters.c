#include "ubond.h"

extern struct ubond_filters_s ubond_filters;
extern struct ubond_filters_s ubond_low_filters;

ubond_tunnel_t *
ubond_filters_choose(uint32_t pktlen, const u_char *pktdata) {
    int i;
    struct pcap_pkthdr hdr;
    ubond_tunnel_t *tun;
    memset(&hdr, 0, sizeof(hdr));
    hdr.caplen = pktlen;
    hdr.len = pktlen;
    for(i = 0; i < ubond_filters.count; i++) {
        tun = ubond_filters.tun[i];
        /* Don't even consider offline interfaces */
        /* log_debug("filters", "check filter[%d] (%s)", i, tun->name); */
        if (pcap_offline_filter(&ubond_filters.filter[i], &hdr, pktdata) != 0) {
            if (tun->status < UBOND_AUTHOK) {
                /* log_debug("filters", "tun %s is offline.", tun->name); */
                continue;
            }
            return tun;
        }
    }
    return NULL;
}

enum ubond_filter_priority ubond_filters_priority(uint32_t pktlen, const u_char *pktdata) {
    int i;
    struct pcap_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.caplen = pktlen;
    hdr.len = pktlen;
    for(i = 0; i < ubond_low_filters.count; i++) {
        /* log_debug("filters", "check filter[%d]", i); */
        if (pcap_offline_filter(&ubond_low_filters.filter[i], &hdr, pktdata) != 0) {
            return UBOND_FILTER_LOW;
        }
    }
    return UBOND_FILTER_HIGH;
}

int
ubond_low_filters_add(const struct bpf_program *filter) {
    if (ubond_low_filters.count >= 255) {
        return -1;
    }
    memcpy(&ubond_low_filters.filter[ubond_low_filters.count], filter, sizeof(*filter));
    ubond_low_filters.count++;
    return 0;
}

int
ubond_filters_add(const struct bpf_program *filter, ubond_tunnel_t *tun) {
    if (ubond_filters.count >= 255) {
        return -1;
    }
    memcpy(&ubond_filters.filter[ubond_filters.count], filter, sizeof(*filter));
    ubond_filters.tun[ubond_filters.count] = tun;
    ubond_filters.count++;
    return 0;
}
