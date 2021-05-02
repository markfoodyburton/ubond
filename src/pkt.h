#ifndef _UBOND_PKT_H
#define _UBOND_PKT_H

#include <stdint.h>
#include <ev.h>

#ifdef HAVE_FREEBSD
#define _NSIG _SIG_MAXSIG
#include <sys/endian.h>
#endif

#include <endian.h>

#ifdef HAVE_DARWIN
#include <libkern/OSByteOrder.h>
#define be16toh OSSwapBigToHostInt16
#define be32toh OSSwapBigToHostInt32
#define be64toh OSSwapBigToHostInt64
#define htobe16 OSSwapHostToBigInt16
#define htobe32 OSSwapHostToBigInt32
#define htobe64 OSSwapHostToBigInt64
#endif

#define DEFAULT_MTU 1500

enum {
    UBOND_PKT_AUTH,
    UBOND_PKT_AUTH_OK,
    UBOND_PKT_KEEPALIVE,
    UBOND_PKT_DATA,
    UBOND_PKT_DATA_RESEND,
    UBOND_PKT_DISCONNECT,
    UBOND_PKT_RESEND,
    UBOND_PKT_TCP_OPEN,
    UBOND_PKT_TCP_CLOSE,
    UBOND_PKT_TCP_DATA,
};


/* packet sent on the wire. 20 bytes headers for ubond */
typedef struct {
    uint16_t len;
    uint8_t type;   /* protocol options 256 type's more than enough */
    uint8_t sent_loss;  /* loss as reported from far end  0-256 more than enough */
    uint16_t timestamp;
    uint16_t timestamp_reply;
    uint16_t tun_seq;  /* Stream sequence used for loss and reordering */
    uint16_t flow_id;  /* surely 65k streams is more than we can cope with anyway? */
    uint16_t data_seq;
    uint16_t ack_seq;
    char data[DEFAULT_MTU];
} __attribute__((packed)) ubond_proto_t;

inline void betoh_proto(ubond_proto_t *proto)
{
    proto->len = be16toh(proto->len);
    proto->timestamp = be16toh(proto->timestamp);
    proto->timestamp_reply = be16toh(proto->timestamp_reply);
    proto->tun_seq = be16toh(proto->tun_seq);
    proto->flow_id = be16toh(proto->flow_id);
    proto->data_seq = be16toh(proto->data_seq);
    proto->ack_seq = be16toh(proto->ack_seq);
}
inline void htobe_proto(ubond_proto_t *proto)
{
    proto->len = htobe16(proto->len);
    proto->timestamp = htobe16(proto->timestamp);
    proto->timestamp_reply = htobe16(proto->timestamp_reply);
    proto->tun_seq = htobe16(proto->tun_seq);
    proto->flow_id = htobe16(proto->flow_id);
    proto->data_seq = htobe16(proto->data_seq);
    proto->ack_seq = htobe16(proto->ack_seq);
}

typedef struct ubond_pkt_t
{
  struct stream_t *stream;  // for sent packets, point to stream if held by TCP stream.
  struct ubond_tunnel_s *sent_tun; // point to tun if it's held in old_pkts list

  ubond_proto_t p;
  ev_tstamp sent_time;
  uint16_t len; // wire read length
  TAILQ_ENTRY(ubond_pkt_t) entry;
} ubond_pkt_t;

typedef struct ubond_pkt_list_t 
{
  TAILQ_HEAD(list_t, ubond_pkt_t) list;
  uint64_t length;
  uint64_t max_size;
} ubond_pkt_list_t;

typedef struct ubond_pkt_challenge
{
  enum {UBOND_CHALLENGE_AUTH, UBOND_CHALLENGE_OK} type;
  uint16_t version;
  uint64_t permitted;
  char password[128];
} ubond_pkt_challenge;

#define UBOND_TAILQ_INIT(lst_) do{TAILQ_INIT(&((lst_)->list));(lst_)->length=0;}while(0)
#define UBOND_TAILQ_INSERT_HEAD(lst_, l) do{TAILQ_INSERT_HEAD(&((lst_)->list), l, entry);(lst_)->length++;}while(0)
#define UBOND_TAILQ_INSERT_TAIL(lst_, l) do{TAILQ_INSERT_TAIL(&((lst_)->list), l, entry);(lst_)->length++;}while(0)
#define UBOND_TAILQ_INSERT_AFTER(lst_, elm, l) do{TAILQ_INSERT_AFTER(&((lst_)->list), elm, l, entry);(lst_)->length++;}while(0)
#define UBOND_TAILQ_INSERT_BEFORE(lst_, elm, l) do{TAILQ_INSERT_BEFORE(elm, l, entry);(lst_)->length++;}while(0)
#define UBOND_TAILQ_REMOVE(lst_, l) do{TAILQ_REMOVE(&((lst_)->list), l, entry);(lst_)->length--;}while(0)
#define UBOND_TAILQ_FOREACH(l, lst_) TAILQ_FOREACH(l, &((lst_)->list), entry)
#define UBOND_TAILQ_FOREACH_REVERSE(l, lst_) TAILQ_FOREACH_REVERSE(l, &((lst_)->list), list_t, entry)
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
