
#ifndef _UBOND_SOCKS_H
#define _UBOND_SOCKS_H

#include <sys/queue.h>

typedef struct stream_t {
    int fd;
    struct ev_io io_read;
    uint32_t flow_id;
    uint32_t their_flow_id;
    uint64_t data_seq;

    TAILQ_ENTRY(stream_t) entry;
} stream_t;

typedef struct stream_list_t 
{
  TAILQ_HEAD(s_list_t, stream_t) list;
  uint64_t length;
  uint64_t max_size;
} stream_list_t;

void socks_init();
int ubond_stream_write();
struct ubond_pkt_t;
void ubond_socks_init(struct ubond_pkt_t* pkt);
void ubond_socks_term(struct ubond_pkt_t* pkt);
void activate_streams();
void pause_streams();

#endif