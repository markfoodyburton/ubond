#ifndef _UBOND_PKT_H
#define _UBOND_PKT_H

#include <stdint.h>
#include <ev.h>
#include "crypto.h"

#define DEFAULT_MTU 1500

enum {
    UBOND_PKT_AUTH,
    UBOND_PKT_AUTH_OK,
    UBOND_PKT_KEEPALIVE,
    UBOND_PKT_DATA,
    UBOND_PKT_DATA_RESEND,
    UBOND_PKT_DISCONNECT,
    UBOND_PKT_RESEND,
    UBOND_PKT_SOCK_OPEN,
    UBOND_PKT_SOCK_CLOSE
};


/* packet sent on the wire. 20 bytes headers for ubond */
typedef struct {
    uint16_t len;
    uint16_t version: 4; /* protocol version */
    uint16_t type: 6;   /* protocol options */
    uint16_t reorder: 1; /* do reordering or not */
    uint16_t sent_loss: 5;  /* loss as reported from far end */
    uint16_t timestamp;
    uint16_t timestamp_reply;
    uint32_t flow_id;
    uint64_t tun_seq;     /* Stream sequence per flow (for crypto) */
    uint64_t data_seq;    /* data packets global sequence */
    char data[DEFAULT_MTU];
} __attribute__((packed)) ubond_proto_t;

typedef struct ubond_pkt_t
{
  ubond_proto_t p;
  ev_tstamp timestamp;
  uint16_t len; // wire read length
  TAILQ_ENTRY(ubond_pkt_t) entry;
} ubond_pkt_t;

typedef struct ubond_pkt_list_t 
{
  TAILQ_HEAD(list_t, ubond_pkt_t) list;
  uint64_t length;
  uint64_t max_size;
} ubond_pkt_list_t;

#define UBOND_TAILQ_INIT(lst_) do{TAILQ_INIT(&((lst_)->list));(lst_)->length=0;}while(0)
#define UBOND_TAILQ_INSERT_HEAD(lst_, l) do{TAILQ_INSERT_HEAD(&((lst_)->list), l, entry);(lst_)->length++;}while(0)
#define UBOND_TAILQ_INSERT_TAIL(lst_, l) do{TAILQ_INSERT_TAIL(&((lst_)->list), l, entry);(lst_)->length++;}while(0)
#define UBOND_TAILQ_INSERT_AFTER(lst_, elm, l) do{TAILQ_INSERT_AFTER(&((lst_)->list), elm, l, entry);(lst_)->length++;}while(0)
#define UBOND_TAILQ_INSERT_BEFORE(lst_, elm, l) do{TAILQ_INSERT_BEFORE(elm, l, entry);(lst_)->length++;}while(0)
#define UBOND_TAILQ_REMOVE(lst_, l) do{TAILQ_REMOVE(&((lst_)->list), l, entry);(lst_)->length--;}while(0)
#define UBOND_TAILQ_FOREACH(l, lst_) TAILQ_FOREACH(l, &((lst_)->list), entry)
#define UBOND_TAILQ_FOREACH_REVERSE(l, lst_) TAILQ_FOREACH(l, &((lst_)->list), list_t, entry)
#define UBOND_TAILQ_EMPTY(lst_) TAILQ_EMPTY(&((lst_)->list))
#define UBOND_TAILQ_FIRST(lst_) TAILQ_FIRST(&((lst_)->list))
#define UBOND_TAILQ_LAST(lst_) TAILQ_LAST(&((lst_)->list), list_t)
#define UBOND_TAILQ_LENGTH(lst_) ((lst_)->length)
static inline ubond_pkt_t *UBOND_TAILQ_POP_LAST(ubond_pkt_list_t *lst)
{
  ubond_pkt_t *l = UBOND_TAILQ_LAST(lst);
  if (l) UBOND_TAILQ_REMOVE(lst, l);
  return l;
}


ubond_pkt_t *ubond_pkt_get();
void ubond_pkt_release(ubond_pkt_t *p);

                                        
#define PKTHDRSIZ(pkt) (sizeof(pkt)-sizeof(pkt.data))
#define ETH_OVERHEAD 24
#define IPV4_OVERHEAD 20
#define TCP_OVERHEAD 20
#define UDP_OVERHEAD 8

#define IP4_UDP_OVERHEAD (IPV4_OVERHEAD + UDP_OVERHEAD)

#endif
