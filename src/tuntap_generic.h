#ifndef UBOND_TUNTAP_GENERIC_H
#define UBOND_TUNTAP_GENERIC_H

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <ev.h>

#include "privsep.h"
#include "ubond.h"

enum tuntap_type {
    UBOND_TUNTAPMODE_TUN,
    UBOND_TUNTAPMODE_TAP
};

struct tuntap_s
{
    int fd;
    int maxmtu;
    char devname[UBOND_IFNAMSIZ];
    enum tuntap_type type;
  ubond_pkt_list_t sbuf; // no longer used
    ev_io io_read;
    ev_io io_write;
};

int ubond_tuntap_alloc(struct tuntap_s *tuntap);
ubond_pkt_t *ubond_tuntap_read(struct tuntap_s *tuntap);
int ubond_tuntap_write(struct tuntap_s *tuntap, ubond_pkt_t *pkt);
int ubond_tuntap_generic_read(u_char *data, uint32_t len);

#endif
