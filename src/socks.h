
#ifndef _UBOND_SOCKS_H
#define _UBOND_SOCKS_H

#include <sys/queue.h>
#include "pkt.h"
#include "ubond.h"

typedef struct tun_insert_t {
  ubond_pkt_t *last_insert;
  uint32_t last_seq;
} tun_insert_t;

typedef struct stream_t {
    int fd;
    struct ev_io io_read;
    struct ev_io io_write;    
    uint16_t flow_id;
    uint16_t preset_flow_id;

    int sending;
    uint32_t data_seq;
    uint32_t seq_to_ack;
    uint32_t next_seq;

    int stall;

    int open;

    ubond_v_pkt_list_t sent;
    ubond_pkt_list_t received;
    ubond_pkt_list_t draining;

    ev_timer resend_timer;
    tun_insert_t tuns[MAX_TUNS];

    TAILQ_ENTRY(stream_t) entry;
} stream_t;

typedef struct stream_list_t 
{
  TAILQ_HEAD(s_list_t, stream_t) list;
  uint64_t length;
  uint64_t max_size;
} stream_list_t;

void socks_init();
void ubond_stream_write(ubond_pkt_t* pkt, ubond_tunnel_t *tunnel);
void ubond_socks_init(struct ubond_pkt_t* pkt);
void tcp_sent(stream_t* s, ubond_pkt_t* pkt);
void activate_streams();
void pause_streams();
int sock_stamp(ubond_pkt_t *pkt);

#endif