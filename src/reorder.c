/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *   Adapted for ubond by Laurent Coustet (c) 2015
 *   Re-worked by Mark Burton (c) 2018 All Rights Reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ev.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>

#include "log.h"
#include "pkt.h"
#include "socks.h"
#include "ubond.h"

#define MAX_REORDERBUF ((uint32_t)10240)
#define MIN_REORDERBUF ((uint32_t)0x20)

#define REORDER_TIMEOUT 0.1
/* The reorder buffer data structure itself */
struct ubond_reorder_buffer {
    uint32_t next; /* current offset in the buffer */
    uint32_t head;
    ubond_pkt_t* buffer[MAX_REORDERBUF];

    enum { REORDER_BUF_RESET,
        REORDER_BUF_SYNCED } state;

    ev_tstamp last_delivery;

    uint32_t data_seq;

    uint32_t start_seq;
    
    uint64_t skipped;
    uint64_t old;
    uint64_t delivered;
    uint64_t resends;
};
static struct ubond_reorder_buffer reorder_buffer;
static ev_timer reorder_timeout_tick;
extern void ubond_rtun_inject_tuntap(ubond_pkt_t* pkt);
extern struct ev_loop* loop;

void ubond_reorder_enable()
{
}

extern float max_size_outoforder;
uint32_t max_size()
{
    int s = max_size_outoforder * 10; // e.g. we consider re-orders up to 10 packets deep - way more than we need.
    if (s < MIN_REORDERBUF)
        return MIN_REORDERBUF;
    if (s > MAX_REORDERBUF/2)
        return MAX_REORDERBUF/2;

    return s;

    //srtt is the time it takes to go there and back. * bandwidth = number of packets in flight?
    //max bandwidth / max
    //So, maybe we should keep enough for max srtt * max bandwith ?
}

inline static int32_t size()
{
    // head is the most recent (farthest ahead) to be inserted
    // next is the next to be delivered, the last delivered is next-1

    if ((int32_t)(reorder_buffer.head - reorder_buffer.next) + 1 < 0) {
        log_warnx("reorder_buffer", "SEQ ID's unmanageably large");
        return MAX_REORDERBUF;
    }
    return (int32_t)(reorder_buffer.head - reorder_buffer.next) + 1;
}
void deliver()
{
    //    not draining ?
    int i = 0;
    
    while (reorder_buffer.buffer[reorder_buffer.next % MAX_REORDERBUF] || size() >= max_size()) {
        if (reorder_buffer.buffer[reorder_buffer.next % MAX_REORDERBUF]) {
            ubond_rtun_inject_tuntap(reorder_buffer.buffer[reorder_buffer.next % MAX_REORDERBUF]);
            i++;
            reorder_buffer.delivered++;
            reorder_buffer.buffer[reorder_buffer.next % MAX_REORDERBUF] = NULL;
        } else {
            reorder_buffer.skipped++;
            log_debug("reorder_buffer", "skipping unrecieved packet (buffer of %d packets, max size %d seq next=0x%x) srtt factor %f", size(), max_size(), reorder_buffer.next, max_size_outoforder);
        }
        reorder_buffer.next++;
    }
    if (i)
        reorder_buffer.last_delivery = ev_now(EV_DEFAULT_UC);
}
void ubond_reorder_tick(EV_P_ ev_timer* w, int revents)
{
    check_watcher(UBOND_REORDER_TICK);
    ev_tstamp now = ev_now(EV_DEFAULT_UC);
    if (size() && ((now - reorder_buffer.last_delivery) > REORDER_TIMEOUT)) {
        /* skip */
        int i = 0;
        while (size() && reorder_buffer.buffer[reorder_buffer.next % MAX_REORDERBUF] == NULL) {
            reorder_buffer.next++;
            i++;
            reorder_buffer.skipped++;
        }
        log_debug("reorder_buffer", "timeout skipping %d unrecieved packets", i);
        deliver();
    }

//    printf("packets %d %d %d %d  %f\n", reorder_buffer.skipped, reorder_buffer.delivered, reorder_buffer.old, reorder_buffer.resends, max_size_outoforder);
}
void ubond_reorder_reset()
{
    /* on reset - drain everything - this could cause some loss, and we might reject 
     * out of order packets. But then we can 'jump' to a new number without problem
     */
    log_warnx("reorder_buffer", "Reorder reset");

    while (size()) {
        if (reorder_buffer.buffer[reorder_buffer.next % MAX_REORDERBUF]) {
            ubond_pkt_release(reorder_buffer.buffer[reorder_buffer.next % MAX_REORDERBUF]);
            // the tuntap will retire the packet when done
            reorder_buffer.buffer[reorder_buffer.next % MAX_REORDERBUF] = NULL;
        }
        reorder_buffer.next++;
    }
    //reorder_buffer.data_seq = 0;
    //reorder_buffer.next = 0;
    //reorder_buffer.head = 0;
    //reorder_buffer.last_delivery = 0;

    reorder_buffer.state = REORDER_BUF_RESET;
}
void ubond_reorder_init()
{
    memset(&reorder_buffer, 0, sizeof(struct ubond_reorder_buffer));
    ubond_reorder_reset();
    ev_timer_init(&reorder_timeout_tick, &ubond_reorder_tick, 0.0, 0.25);
    ev_timer_start(EV_A_ & reorder_timeout_tick);
}

uint32_t next_data_seq()
{
    uint32_t d = reorder_buffer.data_seq++;
    return d;
}

void ubond_reorder_insert(ubond_tunnel_t* tun, ubond_pkt_t* pkt)
{
    if (pkt->p.flow_id) {
        fatalx("Can not re-order TCP stream");
    }

    if (reorder_buffer.state == REORDER_BUF_RESET) {
        reorder_buffer.next = reorder_buffer.head = pkt->p.data_seq;
        reorder_buffer.state = REORDER_BUF_SYNCED;
                        log_warnx("reorder_buffer", "RESETTING from %d to %d",reorder_buffer.head, pkt->p.data_seq);
    }
    

    if (((int32_t)(pkt->p.data_seq - reorder_buffer.next) >= 0) ) {//&& ((int32_t)(reorder_buffer.head + (uint32_t)max_size() - pkt->p.data_seq)>=0)) {

        if ( ((int32_t)(reorder_buffer.head + (0x1000) - pkt->p.data_seq)<0)) {
            log_warnx("reorder_buffer", "ERROR: head %d pkt %d size %d ahead %d",reorder_buffer.head, pkt->p.data_seq, size(), pkt->p.data_seq-reorder_buffer.head);
            //exit(-1);
        }
//its because we got a 'reset' and we chose (randomly) the most 'backward' tunnel
//so then the other tunnel is too far ahead, and boooom.
// but we can ignore, it will only happen once on reset...

//so, lte is falling behind, and it seems to go a loooong way behind - so far, things even wrap round...
//we should consider any tunnel > e.g. 10x slower (too much?) down or lossy or some such
        if (reorder_buffer.buffer[pkt->p.data_seq % MAX_REORDERBUF]) {
            if ((pkt->p.type == UBOND_PKT_DATA_RESEND) && reorder_buffer.buffer[pkt->p.data_seq % MAX_REORDERBUF]->p.data_seq == pkt->p.data_seq) {
                log_debug("reorder_buffer", "redundent resend %d", size());
                ubond_pkt_release(pkt); // we have already got this packet!
                return;
            } else {
                log_warnx("reorder_buffer", "ERROR: Wrapped seq number? size %d 0x%x 0x%x old data seq 0x%x new data seq 0x%x %d %d", size(), reorder_buffer.next, reorder_buffer.head, reorder_buffer.buffer[pkt->p.data_seq % MAX_REORDERBUF]->p.data_seq, pkt->p.data_seq, pkt->len, reorder_buffer.buffer[pkt->p.data_seq % MAX_REORDERBUF]->len);
                ubond_pkt_release(reorder_buffer.buffer[pkt->p.data_seq % MAX_REORDERBUF]);
                reorder_buffer.buffer[pkt->p.data_seq % MAX_REORDERBUF] = NULL;
            }
        }

        if ((int32_t)(pkt->p.data_seq - reorder_buffer.head) > 0) {
            reorder_buffer.head = pkt->p.data_seq;
        }
        if (pkt->p.type == UBOND_PKT_DATA_RESEND) {
            reorder_buffer.resends++;
        }
        reorder_buffer.buffer[pkt->p.data_seq % MAX_REORDERBUF] = pkt;
    } else {
        reorder_buffer.old++;
        ubond_pkt_release(pkt); // we have already got this packet!
//        tun->loss++;
//      setting loss to e.g. 100 is a bit evil, but seems to work !

        log_debug("reorder_buffer", "REJECT PACKET 0x%x from %s (current next 0x%x current head 0x%x max size %d", pkt->p.data_seq, tun->name, reorder_buffer.next, reorder_buffer.head, max_size());

    }
#if 0
    if ((int32_t)(pkt->p.data_seq - (reorder_buffer.head) > 0) 

    if (reorder_buffer.buffer[pkt->p.data_seq % MAX_REORDERBUF]) {
        if ((pkt->p.type == UBOND_PKT_DATA_RESEND) && reorder_buffer.buffer[pkt->p.data_seq % MAX_REORDERBUF]->p.data_seq == pkt->p.data_seq) {
            log_debug("reorder_buffer", "redundent resend %d", size());
            ubond_pkt_release(pkt); // we have already got this packet!
            return;
        } else {
            log_warnx("reorder_buffer", "Wrapped seq number? size %d old data seq 0x%x new data seq 0x%x", size(), reorder_buffer.buffer[pkt->p.data_seq % MAX_REORDERBUF]->p.data_seq, pkt->p.data_seq);
            ubond_pkt_release(reorder_buffer.buffer[pkt->p.data_seq % MAX_REORDERBUF]);
            reorder_buffer.buffer[pkt->p.data_seq % MAX_REORDERBUF] = NULL;
        }
    }

    if ((int32_t)(pkt->p.data_seq - reorder_buffer.head) > 0) {
        reorder_buffer.head = pkt->p.data_seq;
    }
    if ((int32_t)(pkt->p.data_seq - reorder_buffer.next) >= 0) {
        if ((int32_t)(pkt->p.data_seq - reorder_buffer.next) >= max_size()) {
            log_warnx("reorder_buffer", "Adding packet %d ahead (max %d, size %d) (0x%x 0x%x)", (int32_t)(pkt->p.data_seq - reorder_buffer.next), max_size(), size(), pkt->p.data_seq, reorder_buffer.next);
        }
        reorder_buffer.buffer[pkt->p.data_seq % MAX_REORDERBUF] = pkt;
    } else {
        reorder_buffer.old++;
        tun->late++;
        int32_t by = (int32_t)(reorder_buffer.next - pkt->p.data_seq);
        ubond_pkt_release(pkt);
        log_warnx("reorder_buffer", "old seq number - already skipped? late by %d from %s size %d data seq 0x%x  next seq 0x%x ", by, tun->name, size(), pkt->p.data_seq, reorder_buffer.next);
        if (pkt->p.type == UBOND_PKT_DATA_RESEND) {
            log_debug("reorder_buffer", " - redundent resend ? %d", size());
        }
    }
#endif
    deliver();
}

#if 0
/* The reorder buffer data structure itself */
struct ubond_reorder_buffer {
    uint64_t min_seqn; /**< Lowest seq. number that can be in the buffer */
    int is_initialized;
    int enabled;
    int list_size;
    int list_size_max; // used to report only
    uint64_t loss;
    uint64_t delivered;

    ev_tstamp last_tick;
    uint64_t pkts_arrived;
    double pkts_per_sec;
    uint64_t pkts_sent;

    double max_srtt;

    int target_len;

    ubond_pkt_list_t list;

    ev_check reorder_drain_check;
};
static struct ubond_reorder_buffer* reorder_buffer;
//static ev_timer reorder_drain_check;
extern void ubond_rtun_inject_tuntap(ubond_pkt_t* pkt);
extern struct ev_loop* loop;
static ev_timer reorder_timeout_tick;
extern uint64_t out_resends;
extern ev_tstamp resend_at;
extern ubond_pkt_list_t send_buffer; /* send buffer */
void ubond_reorder_reset();

void ubond_reorder_drain();

int aolderb(uint64_t a, uint64_t b)
{
    return ((int64_t)(b - a)) > 0;
}
int aoldereqb(uint64_t a, uint64_t b)
{
    return ((int64_t)(b - a)) >= 0;
}

int ubond_reorder_length()
{
    int r = reorder_buffer->list_size_max;
    reorder_buffer->list_size_max = 0;
    return r;
}

double ubond_total_loss()
{
    float r = 0;

    if (reorder_buffer->loss) {
        r = ((double)reorder_buffer->loss / (double)(reorder_buffer->loss + reorder_buffer->delivered)) * 100.0;
    }
    reorder_buffer->loss = 0;
    reorder_buffer->delivered = 0;

    return r;
}

void ubond_reorder_drain_check(EV_P_ ev_check* w, int revents)
{
    struct ubond_reorder_buffer* b = reorder_buffer;
    ev_tstamp now = ev_now(EV_DEFAULT_UC);
    ev_tstamp diff = now - b->last_tick;

    if (b->pkts_sent < b->pkts_per_sec * diff) {
        b->pkts_sent++;
        ubond_reorder_drain();
    }
}

void ubond_reorder_tick(EV_P_ ev_timer* w, int revents)
{
    struct ubond_reorder_buffer* b = reorder_buffer;
    ubond_tunnel_t* t;
    double max_srtt = 0.0;

    ev_tstamp now = ev_now(EV_DEFAULT_UC);
    ev_tstamp diff = now - b->last_tick;
    b->last_tick = now;

    int up = 0;
    LIST_FOREACH(t, &rtuns, entries)
    {

        //    worst 'reorder time' for any tunnel  /  fastest tunnel
        //                                   +
        //                                   process/wait time
        //                                   + srtt

        if (t->status >= UBOND_AUTHOK)
            up++;
        if (t->status == UBOND_AUTHOK && !t->fallback_only) {
            /* We don't want to monitor fallback only links inside the
       * reorder timeout algorithm
       */
            if (t->srtt_av > max_srtt) {
                max_srtt = t->srtt_av;
            }
        }
    }
    if (up == 0 && b->is_initialized) {
        log_warnx("reorder", "No Tunnels hence resetting\n");
        b->is_initialized = 0;
    }

    if (max_srtt <= 0) {
        max_srtt = 800;
    }

    b->max_srtt = (b->max_srtt * 9 + max_srtt) / 10;

    if (diff) {
        //    9/10 is too long, but 0 is too short?
        //      shorter tick, and 4/5 seems to be about right
        double pps = ((float)b->pkts_arrived / (float)diff);
        if (pps > b->pkts_per_sec) {
            b->pkts_per_sec = (pps + (pps - b->pkts_per_sec)) * 2;
        } else {
            b->pkts_per_sec = ((b->pkts_per_sec * 4.0) + pps) / 5.0;
        }

    } else {
        b->pkts_per_sec = (float)b->pkts_arrived;
    }
    b->pkts_sent = 0;
    b->pkts_arrived = 0;
    if (b->pkts_per_sec < 1000)
        b->pkts_per_sec = 1000;
    // this seems to be critical for video?
    // Too high, it fails, too low it fails...???

    //  log_debug("reorder", "adjusting reordering drain timeout to %.0fms", reorder_drain_timeout.repeat*1000 );
}

// Called once from main.
void ubond_reorder_init()
{
    reorder_buffer = malloc(sizeof(struct ubond_reorder_buffer));
    UBOND_TAILQ_INIT(&reorder_buffer->list);
    reorder_buffer->enabled = 0;
    ubond_reorder_reset();

    ev_check_init(&reorder_buffer->reorder_drain_check, ubond_reorder_drain_check);

    ev_timer_init(&reorder_timeout_tick, &ubond_reorder_tick, 0., 0.25);
    ev_timer_start(EV_A_ & reorder_timeout_tick);
}

//called from main, or from config
void ubond_reorder_reset()
{
    log_warnx("reorder", "Reset");
    struct ubond_reorder_buffer* b = reorder_buffer;
    while (!UBOND_TAILQ_EMPTY(&b->list)) {
        ubond_pkt_release(UBOND_TAILQ_POP_LAST(&b->list));
    }
    b->list_size = 0;
    b->list_size_max = 0;
    b->is_initialized = 0;
    b->last_tick = 0;
    b->pkts_arrived = 0;
    b->pkts_per_sec = 1;
    b->pkts_sent = 0;
    b->max_srtt = 0.1;
    b->target_len = 1000;
}

void ubond_reorder_enable()
{
    reorder_buffer->enabled = 1;
}

wouldnt this be better as just a e.g .1024 array - if you hit within the last 1024, great, if not forget it equally - keep track of which tunnels have new thing, when all tunnels have at least e.g .2, then we can be sure its a loss, and we should just move on.

                                                                                                                                                                                                                                             extern int
                                                                                                                                                                                                                                             is_tcp(ubond_pkt_t*pkt);
void ubond_reorder_insert(ubond_tunnel_t* tun, ubond_pkt_t* pkt)
{
    struct ubond_reorder_buffer* b = reorder_buffer;
    b->pkts_arrived++;

    if (is_tcp(pkt) && (!b->is_initialized || ((int64_t)(b->min_seqn - pkt->p.data_seq) > 1000 && pkt->p.data_seq < 1000))) {
        b->min_seqn = pkt->p.data_seq;
        b->is_initialized = 1;
        log_warnx("reorder", "initial sequence: %" PRIu64 "", pkt->p.data_seq);
    }

    if (pkt->p.type == UBOND_PKT_DATA_RESEND) {
        // we could count in each tunnel the number of non resends, if you get to
        // 'reorder' in each tunnel, you know you wont receive anymore resends
        if (out_resends > 0)
            out_resends--;
    }

    if (!b->enabled || !is_tcp(pkt) || !pkt->p.data_seq /* || pkt->p.data_seq==b->min_seqn*/) {
        if (!ubond_stream_write(pkt))
            ubond_rtun_inject_tuntap(pkt); // this will deliver and free the packet
        // Deliver non reordable packets ASAP, as that shoudn't effect a tcp algorithm
        b->delivered++;
        return;
    }

    if (pkt->p.type == UBOND_PKT_DATA_RESEND /* && pkt->p.data_seq && pkt->p.reorder*/) {

        if (aolderb(pkt->p.data_seq, b->min_seqn)) {
            log_debug("resend", "Rejecting (un-necissary ?) resend %lu", pkt->p.data_seq);
            ubond_pkt_release(pkt);
            return;
        } else {
            log_debug("resend", "Injecting resent %lu", pkt->p.data_seq);
        }
    }
    if (aolderb(pkt->p.data_seq, b->min_seqn)) {
        log_debug("loss", "got old insert %d behind (probably agressive pruning) on %s", (int)(b->min_seqn - pkt->p.data_seq), tun->name);
        b->loss++;
        ubond_pkt_release(pkt);
        return;
    }

    pkt->timestamp = ev_now(EV_DEFAULT_UC);

    /*
     * calculate the offset from the head pointer we need to go.
     * The subtraction takes care of the sequence number wrapping.
     * For example (using 16-bit for brevity):
     *  min_seqn  = 0xFFFD
     *  pkt_seq   = 0x0010
     *  offset    = 0x0010 - 0xFFFD = 0x13
     * Then we cast to a signed int, if the subtraction ends up in a large
     * number, that will be seen as negative when casted....
     */
    ubond_pkt_t* l;
    // we could search from the other end if it's closer?
    UBOND_TAILQ_FOREACH(l, &b->list)
    {
        if (pkt->p.data_seq == l->p.data_seq) { // replicated packet!
            log_debug("resend", "Un-necissary resend %lu", pkt->p.data_seq);
            ubond_pkt_release(pkt);
            return;
        }
        if (aolderb(l->p.data_seq, pkt->p.data_seq))
            break;
    }
    if (l) {
        UBOND_TAILQ_INSERT_BEFORE(&b->list, l, pkt);
    } else {
        UBOND_TAILQ_INSERT_TAIL(&b->list, pkt);
    }

    b->list_size++;
    if (b->list_size > b->list_size_max) {
        b->list_size_max = b->list_size;
    }

    if (!ev_is_active(&b->reorder_drain_check)) {
        ev_check_start(EV_A_ & b->reorder_drain_check);
    }
    //  ubond_reorder_drain();
}

extern double srtt_min;
void ubond_reorder_drain()
{
    struct ubond_reorder_buffer* b = reorder_buffer;
    unsigned int drain_cnt = 0;
    // 2.2 is a good window size
    // 3 * more when we have resends (there and back + processing time etc)

    /*some NS t respod - lest say 150
    then - lest say we wnt to be able to handle 50 errors
    so - 50* the delay it takes to send - say 10 per?
    then -the other end - another 150 + another 50* - so everything *2

    ((150 + 50*10)*2)*2 = 2.6
    + the SRTT

    thats how many we want IN THE QUEUE
    so if we're /2, then we have to *2....*/

    ev_tstamp now = ev_now(EV_DEFAULT_UC);
    ev_tstamp t = ((/*(double)b->*/ srtt_min * 3 / 1000.0) * 2.2); //+2.6; // +300ms processing time

    if (resend_at < (now - (2.2 * (/*(double)b->*/ srtt_min * 3 / 1000.0)))) {
        // we're never going to get a resend, you may as well drop!
    } else {
        t += 2.6;
    }

    ev_tstamp cut = now - t;
    int target_len = (b->pkts_per_sec * t);
    if (target_len > RESENDBUFSIZE)
        target_len = RESENDBUFSIZE;
    if (target_len > b->target_len) {
        b->target_len = target_len;
    } else {
        if (b->list_size < target_len) {
            b->target_len = target_len;
        }
    }

    /* We should
  deliver all packets in order
    Packets that are 'before' the current 'minium' - drop
    Packets that are 'after' the current 'minimum' hold - till the cut-off time,
      then deliver

  We would love a list that was equal to the number of things we need such
  that (max_srtt*2 + processing, + other things in the resend queue) time can
  pass, and we'll still be able to fill in wih resends...
  Lets call that max_srtt*6.6 (as above)

  But, no point having a length greater than  we could be asking for
  (e.g. that could be found in the pkt list)
*/

    while (!UBOND_TAILQ_EMPTY(&b->list) && (aoldereqb(UBOND_TAILQ_LAST(&b->list)->p.data_seq, b->min_seqn) || (UBOND_TAILQ_LAST(&b->list)->timestamp < cut) || (b->list_size > b->target_len))) {

        //    if (!aoldereqb(UBOND_TAILQ_LAST(&b->list)->p.data_seq, b->min_seqn) ) {
        //      log_debug("loss","Clearing: list size %d target %d last %f cut %f (%fs ago now: %fs)  outstanding resends %lu", b->list_size, b->target_len, UBOND_TAILQ_LAST(&b->list)->timestamp, cut, t, now,  out_resends);
        //    }
        ubond_pkt_t* l = UBOND_TAILQ_LAST(&b->list);
        UBOND_TAILQ_REMOVE(&b->list, l);

        b->list_size--;
        drain_cnt++;

        if (l->p.data_seq == b->min_seqn) { // normal delivery
            if (!ubond_stream_write(l))
                ubond_rtun_inject_tuntap(l);
            b->delivered++;
            log_debug("reorder", "Delivered data seq %lu (tun seq %lu)", l->p.data_seq, l->p.tun_seq);
            b->min_seqn = l->p.data_seq + 1;
            if (b->list_size < (b->target_len / 2))
                break;
        } else if (aolderb(b->min_seqn, l->p.data_seq)) { // cut off time reached
            ubond_rtun_inject_tuntap(l);
            b->delivered++;
            b->loss += l->p.data_seq - b->min_seqn;
            log_debug("loss", "Lost %d from %lu, Delivered %lu (tun seq %lu)", (int)(l->p.data_seq - b->min_seqn), b->min_seqn, l->p.data_seq, l->p.tun_seq);
            b->min_seqn = l->p.data_seq + 1;
        } else {
            ubond_pkt_release(l);
            b->loss++;
            log_debug("loss", "Lost %lu, (trying to deliver %lu) (tun seq %lu)", l->p.data_seq, b->min_seqn, l->p.tun_seq);
        }
    }

    if (out_resends > b->list_size)
        out_resends = b->list_size;

    if (UBOND_TAILQ_EMPTY(&b->list)) {
        if (ev_is_active(&b->reorder_drain_check)) {
            ev_check_stop(EV_A_ & b->reorder_drain_check);
        }
    }
}
#endif