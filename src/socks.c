
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "privsep.h"
#include "socks.h"
#include "ubond.h"

#define TCP_MAX_OUTSTANDING 1024

int aolderb(uint16_t a, uint16_t b)
{
    return ((int16_t)(b - a)) > 0;
}
int aoldereqb(uint16_t a, uint16_t b)
{
    return ((int16_t)(b - a)) >= 0;
}

extern struct ubond_options_s ubond_options;
extern ubond_pkt_list_t send_buffer; /* send buffer */
extern ubond_pkt_list_t hpsend_buffer; /* send buffer */
extern float max_size_outoforder;

static int setnonblock(int fd);

#define MAXSTREAMS 10000
ev_io socks_read;

stream_list_t active;

stream_list_t s_pool;
uint64_t s_pool_out = 0;
uint32_t max_flow_id = 1; // flowid of 0 is illegal
stream_t* ubond_stream_get()
{
    stream_t* p;
    if (!UBOND_TAILQ_EMPTY(&s_pool)) {
        p = UBOND_TAILQ_FIRST(&s_pool);
        UBOND_TAILQ_REMOVE(&s_pool, p);
    } else {
        p = malloc(sizeof(struct stream_t));
        assert(p); // otherwise we are truely doomed.
        p->preset_flow_id = max_flow_id++; // NB, set once, and re-used when reallocated from the pool
        if (max_flow_id > MAXSTREAMS) {
            log_warnx("socks", "Using more TCP streams (%d) that configured (%d)", max_flow_id, MAXSTREAMS);
        }
    }
    s_pool_out++;

    return p;
};
void ubond_stream_release(stream_t* p)
{
    s_pool_out--;
    UBOND_TAILQ_INSERT_HEAD(&s_pool, p);
}
void ubond_stream_list_init(stream_list_t* list, uint64_t size)
{
    UBOND_TAILQ_INIT(list);
    list->max_size = size;
}

static void ubond_stream_close(stream_t* s)
{
    log_warnx("sock", "Stream Closing (FD:%d)", s->fd);
    if (ev_is_active(&s->io_read)) {
        ev_io_stop(EV_DEFAULT_ & s->io_read);
    }
    close(s->fd);

    while (1) {
        ubond_pkt_t* l = UBOND_TAILQ_FIRST(&s->sent);
        if (!l)
            break;
        UBOND_TAILQ_REMOVE(&s->sent, l);
        ubond_pkt_release(l);
    }
    while (1) {
        ubond_pkt_t* l = UBOND_TAILQ_FIRST(&s->received);
        if (!l)
            break;
        UBOND_TAILQ_REMOVE(&s->received, l);
        ubond_pkt_release(l);
    }

    UBOND_TAILQ_REMOVE(&active, s);
    ubond_stream_release(s);

    if (UBOND_TAILQ_LENGTH(&active) >= MAXSTREAMS) {
        if (!ev_is_active(&socks_read)) {
            ev_io_start(EV_DEFAULT_ & socks_read);
        }
    }
}

int paused = 0;
void activate_streams()
{
    if (paused == 0 || ubond_pkt_list_is_full(&send_buffer))
        return;
    else {
        //printf("Activate\n");
        stream_t* l;
        UBOND_TAILQ_FOREACH(l, &active)
        {
            if (l->sent.length < TCP_MAX_OUTSTANDING) {
                ev_io_start(EV_DEFAULT_ & l->io_read);
            }
        }
        paused = 0;
    }
}

void pause_streams()
{
    //printf("Pause\n");
    stream_t* l;
    UBOND_TAILQ_FOREACH(l, &active)
    {
        ev_io_stop(EV_DEFAULT_ & l->io_read);
    }
    paused = 1;
}

stream_t* find(ubond_pkt_t* pkt)
{
    stream_t* l;
    if (!pkt->p.flow_id)
        return NULL;

    UBOND_TAILQ_FOREACH(l, &active)
    {
        if (l->flow_id == pkt->p.flow_id)
            return l;
    }
    return NULL;
}

void send_pkt_tun(stream_t* s, ubond_pkt_t* pkt, uint16_t type)
{
    pkt->stream = s;
    pkt->sent_tun = NULL;
    pkt->p.data_seq = s->data_seq++;
    pkt->p.flow_id = s->flow_id;
    pkt->p.type = type;

    pkt->p.ack_seq = s->seq_to_ack; // stamp the last delivered pack ack
    s->sending++;

    ubond_buffer_write(&send_buffer, pkt);
}

void resend(stream_t* s)
{
    ubond_pkt_t* l = UBOND_TAILQ_FIRST(&s->sent);

    /* remove it from the old tunnel */
    if (l->sent_tun) { // tun may be keeping it
        l->sent_tun->old_pkts[l->p.tun_seq % RESENDBUFSIZE] = NULL;
        l->sent_tun = NULL;
    }
    l->p.ack_seq = s->seq_to_ack; // restamp the uptodate ack
    s->sending++;
    ubond_buffer_write(&send_buffer, l);
}

// could be client or server
void ubond_stream_write(ubond_pkt_t* pkt)
{
    stream_t* s = find(pkt);
    if (!s)
        return;
    pkt->stream = s;

    if (s->sending == 0)
        ev_feed_fd_event(EV_DEFAULT_ s->fd, EV_READ); // triggure a read event, just in case we got blocked.

    /* first check off the things from the 'sent' queue */
    int acks = 0;
    while (1) {
        ubond_pkt_t* l = UBOND_TAILQ_FIRST(&s->sent);
        if (l && aoldereqb(l->p.data_seq, pkt->p.ack_seq)) {
            UBOND_TAILQ_REMOVE(&s->sent, l);
            if (l->sent_tun) // tun may be keeping it
            {
                // we do not need this packet to be re-sent it's been ACK'd
                l->sent_tun->old_pkts[l->p.tun_seq % RESENDBUFSIZE] = NULL;
                l->sent_tun = NULL;
                l->stream = NULL;
            }
            acks++;
            ubond_pkt_release(l);
            if (l->p.type == UBOND_PKT_TCP_CLOSE) {
                ubond_stream_close(s);
                break;
            }
            if (l->p.data_seq == pkt->p.ack_seq) {
                break;
            }

        } else {
            log_warnx("tcp", "Unable to find ACK package in sent list");
            break;
        }
    }
    if (!acks && s->sent.length > max_size_outoforder + 1) { // round max_size up.
        ubond_pkt_t* l = UBOND_TAILQ_FIRST(&s->sent);
        resend(s);
    }
    if (s->sent.length < TCP_MAX_OUTSTANDING) {
        if (!paused) {
            ev_io_start(EV_DEFAULT_ & s->io_read);
        }
    }

    /* now insert in the received queue */
    ubond_pkt_t* l;
    // we could search from the other end if it's closer?
    UBOND_TAILQ_FOREACH(l, &s->received)
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
        UBOND_TAILQ_INSERT_BEFORE(&s->received, l, pkt);
    } else {
        UBOND_TAILQ_INSERT_TAIL(&s->received, pkt);
    }

    /* drain */
    int drained = 0;
    while (!UBOND_TAILQ_EMPTY(&s->received) && (UBOND_TAILQ_LAST(&s->received)->p.data_seq == s->next_seq)) {

        ubond_pkt_t* l = UBOND_TAILQ_LAST(&s->received);
        UBOND_TAILQ_REMOVE(&s->received, l);

        s->seq_to_ack = pkt->p.data_seq;
        s->next_seq = s->seq_to_ack + 1;
        drained++;

        if (pkt->p.type == UBOND_PKT_TCP_CLOSE) { // this is an ACK on our request to close, so we can now close
            ubond_stream_close(s);
        } else {
            int ret = write(s->fd, pkt->p.data, pkt->p.len);
            if (ret != pkt->p.len) {
                log_warn("sock", "write error: %zd/%d bytes sent (closing stream) ", ret, pkt->p.len);
                ubond_pkt_t* p = ubond_pkt_get();
                p->p.len = 0;
                send_pkt_tun(s, p, UBOND_PKT_TCP_CLOSE);
            }
        }
        ubond_pkt_release(pkt);
    }
    if (drained && !s->sending) {
        ubond_pkt_t* p = ubond_pkt_get();
        p->p.len = 0;
        send_pkt_tun(s, p, UBOND_PKT_TCP_DATA);
    }
}

// called once the packet is sent
void tcp_sent(stream_t* s, ubond_pkt_t* pkt)
{
    UBOND_TAILQ_INSERT_TAIL(&s->sent, pkt);

    if (s->sent.length >= TCP_MAX_OUTSTANDING) {
        ev_io_stop(EV_DEFAULT_ & s->io_read);
    }

    s->sending--;
}

//recieve a packet and set it up to be sent
// could be server or client side
static void on_read_cb(struct ev_loop* loop, struct ev_io* ev, int revents)
{
    int rv;
    char buf[DEFAULT_MTU];
    stream_t* s = (stream_t*)ev->data;
    ubond_pkt_t* pkt;

    do {
        pkt = ubond_pkt_get();
        //printf("fetching %d %d %d\n", ev->fd, s->fd, ubond_options.mtu);
        if (ubond_pkt_list_is_full(&send_buffer))
            break;
        rv = recv(ev->fd, &pkt->p.data, ubond_options.mtu, MSG_DONTWAIT);
        if (rv < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                //printf("Would block\n");
                ubond_pkt_release(pkt);
                break;
            } else {
                log_warn("sock", "stream closing ");
                pkt->p.len = 0;
                send_pkt_tun(s, pkt, UBOND_PKT_TCP_CLOSE);
                break;
            }
        } else {
            //printf("Send packet\n");
            pkt->p.len = rv;
            send_pkt_tun(s, pkt, UBOND_PKT_TCP_DATA);
        }
    } while (rv > 0);

    if (ubond_pkt_list_is_full(&send_buffer)) {
        pause_streams();
    }
}

static void on_accept_cb(struct ev_loop* loop, struct ev_io* ev, int revents)
{
    stream_t* s;
    struct sockaddr cliaddr;
    socklen_t clilen = sizeof(cliaddr);

    /* libev is level-triggering so don't have to loop accept */
    int fd = accept(ev->fd, (struct sockaddr*)&cliaddr, &clilen);
    getsockname(fd, (struct sockaddr*)&cliaddr, &clilen);
    if (fd < 0)
        return;
    setnonblock(fd);

    log_info("socks", "New stream addr %u port %s (FD:%d)", ntohs(((struct sockaddr_in*)&cliaddr)->sin_port), inet_ntoa(((struct sockaddr_in*)&cliaddr)->sin_addr), fd);

    stream_t* stream;
    stream = ubond_stream_get();
    stream->fd = fd;
    stream->data_seq = 0;
    ev_io_init(&stream->io_read, on_read_cb, fd, EV_READ);
    stream->io_read.data = (void*)stream;
    stream->flow_id = stream->preset_flow_id; // we set the flowID
    stream->sending = 0;
    stream->seq_to_ack = 0;
    stream->next_seq = 0;

    UBOND_TAILQ_INIT(&stream->sent);
    UBOND_TAILQ_INIT(&stream->received);

    ubond_pkt_t* pkt = ubond_pkt_get();
    if (ubond_pkt_list_is_full(&hpsend_buffer)) {
        log_warnx("sock", "Unable to proccess accept into HP send buffer");
        ubond_stream_close(stream); // this is 'final', the other side hasn't even opened yet
        return;
    }

    UBOND_TAILQ_INSERT_TAIL(&active, stream);
    if (!paused)
        ev_io_start(EV_DEFAULT_ & stream->io_read);

    struct sockaddr* d = (struct sockaddr*)(pkt->p.data);
    *d = cliaddr;

    pkt->p.len = sizeof(struct sockaddr);
    pkt->p.flow_id = stream->flow_id;
    pkt->p.data_seq = stream->data_seq++;
    pkt->p.type = UBOND_PKT_TCP_OPEN;
    ubond_buffer_write(&hpsend_buffer, pkt);
}

void socks_init()
{
    UBOND_TAILQ_INIT(&s_pool);
    ubond_stream_list_init(&active, MAXSTREAMS);

    short bindport = ubond_options.tcp_socket;
    if (!bindport) {
        log_warnx("socks", "No TCP tunnel : (config tcp_socket set to 0)");
        return;
    }

    int serverfd = priv_set_socket_transparent(bindport);

    ev_io_init(&socks_read, on_accept_cb, serverfd, EV_READ);
    ev_io_start(EV_DEFAULT_ & socks_read);
    log_info("socks", "TCP Socket tunnel up on port %d", bindport);
    return;
}

static int setnonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return -1;
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0)
        return -1;

    return 0;
}

/*
 *  server side
*/

void ubond_socks_init(ubond_pkt_t* pkt)
{
    struct sockaddr* rp = (struct sockaddr*)(pkt->p.data);

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        log_warn("sock", "Unable to open socket ");
        return;
    }
    int r = connect(fd, rp, sizeof(struct sockaddr));
    if (r < 0) {
        log_warn("sock", "Unable to connect socket ");
        close(fd);
        return;
    }

    stream_t* s;
    s = ubond_stream_get();
    s->fd = fd;
    s->flow_id = pkt->p.flow_id; // THEY set the flowid
    s->data_seq = 0;
    ev_io_init(&s->io_read, on_read_cb, fd, EV_READ);
    s->io_read.data = (void*)s;

    UBOND_TAILQ_INSERT_TAIL(&active, s);
    if (!paused)
        ev_io_start(EV_DEFAULT_ & s->io_read);
}
