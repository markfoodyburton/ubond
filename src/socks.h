
#ifndef _UBOND_SOCKS_H
#define _UBOND_SOCKS_H

#include <sys/queue.h>
#include "pkt.h"

typedef struct stream_t {
    int fd;
    struct ev_io io_read;
    uint16_t flow_id;
    uint16_t preset_flow_id;
    uint16_t data_seq;

    int sending;
    uint16_t seq_to_ack;
    uint16_t next_seq;

    ubond_pkt_list_t sent;
    ubond_pkt_list_t received;

    TAILQ_ENTRY(stream_t) entry;
} stream_t;

typedef struct stream_list_t 
{
  TAILQ_HEAD(s_list_t, stream_t) list;
  uint64_t length;
  uint64_t max_size;
} stream_list_t;

void socks_init();
void ubond_stream_write();
struct ubond_pkt_t;
void ubond_socks_init(struct ubond_pkt_t* pkt);
void tcp_sent(stream_t* s, ubond_pkt_t* pkt);
void activate_streams();
void pause_streams();

#endif