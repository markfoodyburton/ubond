
#include <stdlib.h>

#include "pkt.h"
#include "log.h"

ubond_pkt_list_t pool;
uint64_t pool_out = 0;
ubond_v_pkt_list_t v_pool;
uint64_t v_pool_out = 0;

void ubond_init_pkts()
{
    UBOND_TAILQ_INIT(&pool);
    UBOND_TAILQ_INIT(&v_pool);

    for (int i=i; i<100000; i++) {
        ubond_pkt_t *p=ubond_pkt_get();
        ubond_v_pkt_release(ubond_v_pkt_get(p));
        ubond_pkt_release(p);
    }
}

ubond_pkt_t* ubond_pkt_get()
{
    ubond_pkt_t* p;
    if (!UBOND_TAILQ_EMPTY(&pool)) {
        p = UBOND_TAILQ_FIRST(&pool);
        UBOND_TAILQ_REMOVE(&pool, p);
    } else {
        p = malloc(sizeof(struct ubond_pkt_t));
        p->usecnt = 0;
    }
//    p->stream = NULL;
    if (p->usecnt != 0) {
        fatalx("USECNT !=0 (get)");
    }
    p->usecnt++;
    pool_out++;
    return p;
}
void ubond_pkt_release_s(ubond_pkt_t* p)
{
    if (p->usecnt < 1) {
        fatalx("USECNT <1 (safe pkt release)");
    }
    if (p->usecnt == 1) {
        ubond_pkt_release(p);
    } else {
        p->usecnt--;
    }
}
void ubond_pkt_release(ubond_pkt_t* p)
{
    //    if (p->sent_tun) {
    //        log_warnx("PKT", "Packet has sent_tun on release?");
    //    }
    pool_out--;

    p->usecnt--;
    if (p->usecnt != 0) {
        fatalx("USECNT !=0 (release)");
    }
    UBOND_TAILQ_INSERT_HEAD(&pool, p);
}
void ubond_pkt_insert(ubond_pkt_list_t* list, ubond_pkt_t* pkt)
{
    if (list->length >= list->max_size) {
        log_warnx("lists", "buffer overflow");
    }
    UBOND_TAILQ_INSERT_HEAD(list, pkt);
}
int ubond_pkt_list_is_full(ubond_pkt_list_t* list)
{
    return (list->length >= list->max_size);
}
int ubond_pkt_list_is_full_watermark(ubond_pkt_list_t* list)
{
    return (list->length >= (list->max_size) / 2);
}
void ubond_pkt_list_init(ubond_pkt_list_t* list, uint64_t size)
{
    UBOND_TAILQ_INIT(list);
    list->max_size = size;
}

ubond_v_pkt_t* ubond_v_pkt_get(ubond_pkt_t* pkt)
{
    ubond_v_pkt_t* p;
    if (!UBOND_TAILQ_EMPTY(&v_pool)) {
        p = UBOND_TAILQ_FIRST(&v_pool);
        UBOND_TAILQ_REMOVE(&v_pool, p);
    } else {
        p = malloc(sizeof(struct ubond_v_pkt_t));
    }
    p->pkt = pkt;
    if (p->pkt->usecnt == 0) {
        fatalx("USECNT ==0 (virtual get)");
    }
    p->pkt->usecnt++;
    v_pool_out++;
    return p;
}
void ubond_v_pkt_release(ubond_v_pkt_t* p)
{
    if (p->pkt->usecnt < 1) {
        fatalx("USECNT <1 (virtual release)");
    }
    if (p->pkt->usecnt == 1) {
        ubond_pkt_release(p->pkt);
    } else {
        p->pkt->usecnt--;
    }
    v_pool_out--;
    UBOND_TAILQ_INSERT_HEAD(&v_pool, p);
}