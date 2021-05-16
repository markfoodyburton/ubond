
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
    if (ev_is_active(&s->io_write)) {
        ev_io_stop(EV_DEFAULT_ & s->io_write);
    }
    close(s->fd);

    while (!UBOND_TAILQ_EMPTY(&s->sent)) {
        ubond_pkt_t* l = UBOND_TAILQ_FIRST(&s->sent);
        UBOND_TAILQ_REMOVE(&s->sent, l);
        ubond_pkt_release(l);
    }
    while (!UBOND_TAILQ_EMPTY(&s->received)) {
        ubond_pkt_t* l = UBOND_TAILQ_FIRST(&s->received);
        UBOND_TAILQ_REMOVE(&s->received, l);
        ubond_pkt_release(l);
    }
    while (!UBOND_TAILQ_EMPTY(&s->draining)) {
        ubond_pkt_t* l = UBOND_TAILQ_FIRST(&s->draining);
        UBOND_TAILQ_REMOVE(&s->draining, l);
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
    if (paused == 0 || ubond_pkt_list_is_full_watermark(&send_buffer))
        return;
    else {
        printf("Activate\n");
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
    printf("Pause\n");
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
    //pkt->sent_tun = NULL;
    if (type == UBOND_PKT_TCP_ACK) {
        pkt->p.data_seq = 0;
    } else {
        pkt->p.data_seq = s->data_seq++;
    }

    pkt->p.flow_id = s->flow_id;
    pkt->p.type = type;

    pkt->p.ack_seq = s->seq_to_ack; // stamp the last delivered pack ack
    s->sending++;

    log_debug("tcp", "Sending package %d to tunnel (ack %d type %d len %d)", pkt->p.data_seq, pkt->p.ack_seq, pkt->p.type, pkt->p.len);

    ubond_buffer_write(&send_buffer, pkt);
    if (ubond_pkt_list_is_full(&send_buffer)) {
        log_warnx("tcp", "Send buffer is full !");
    }
}

void stamp(stream_t* s)
{
    ubond_pkt_t* l;
    UBOND_TAILQ_FOREACH_REVERSE(l, &send_buffer)
    {
        if (l->p.type == UBOND_PKT_TCP_DATA || l->p.type == UBOND_PKT_TCP_ACK) {
            l->p.ack_seq = s->seq_to_ack;
            return;
        }
    }
    ubond_pkt_t* p = ubond_pkt_get();
    p->p.len = 0;
    send_pkt_tun(s, p, UBOND_PKT_TCP_ACK);
}

void resend(stream_t* s)
{
    return;
    ubond_pkt_t* l = UBOND_TAILQ_FIRST(&s->sent);
    if (ubond_pkt_list_is_full(&send_buffer)) {
        log_warnx("tcp", "Send buffer is full !");
        return;
    }

    log_debug("tcp", "Resend as we have no ack %d package in sent list", l->p.ack_seq);

    /* remove it from the old tunnel */
    //    if (l->sent_tun) { // tun may be keeping it
    //        l->sent_tun->old_pkts[l->p.tun_seq % RESENDBUFSIZE] = NULL;
    //        l->sent_tun = NULL;
    //    }
    l->p.ack_seq = s->seq_to_ack; // restamp the uptodate ack
    s->sending++;
    ubond_buffer_write(&hpsend_buffer, l);
}

// could be client or server
void ubond_stream_write(ubond_pkt_t* pkt)
{
    log_debug("tcp", "Recieved packet %d (type %d, length %d) from tunnel", pkt->p.data_seq, pkt->p.type, pkt->p.len);

    stream_t* s = find(pkt);
    if (!s)
        return;
    pkt->stream = s;

    if (s->sending == 0)
        ev_feed_fd_event(EV_DEFAULT_ s->fd, EV_READ); // triggure a read event, just in case we got blocked.

    /* first check off the things from the 'sent' queue */
    int acks = 0;
    while (!UBOND_TAILQ_EMPTY(&s->sent)) {
        ubond_pkt_t* l = UBOND_TAILQ_FIRST(&s->sent);
        if (l && aoldereqb(l->p.data_seq, pkt->p.ack_seq)) {
            UBOND_TAILQ_REMOVE(&s->sent, l);
            //            if (l->sent_tun) // tun may be keeping it
            //            {
            //                // we do not need this packet to be re-sent it's been ACK'd
            //                l->sent_tun->old_pkts[l->p.tun_seq % RESENDBUFSIZE] = NULL;
            //        l->sent_tun = NULL;
            l->stream = NULL;
            //            }
            acks++;
            log_debug("tcp", "Found ACK'd package %d (ack to %d) in sent list", l->p.data_seq, pkt->p.ack_seq);
            ubond_pkt_release(l);
            if (l->p.type == UBOND_PKT_TCP_CLOSE) {
                ubond_stream_close(s);
                break;
            }
            if (l->p.data_seq == pkt->p.ack_seq) {
                break;
            }

        } else {
            log_debug("tcp", "Unable to find ACK %d package in sent list", pkt->p.ack_seq);
            break;
        }
    }
    if (!acks && s->sent.length > (max_size_outoforder * 10) + 1) { // round max_size up.
        resend(s);
    }
    if (s->sent.length < TCP_MAX_OUTSTANDING) {
        if (!paused) {
            ev_io_start(EV_DEFAULT_ & s->io_read);
        }
    }

    if (pkt->p.type != UBOND_PKT_TCP_ACK) {
        /* now insert in the received queue */
        ubond_pkt_t* l;
        // we could search from the other end if it's closer?
        UBOND_TAILQ_FOREACH(l, &s->received)
        {
            if (pkt->p.data_seq == l->p.data_seq) { // replicated packet!
                log_debug("tcp", "Un-necissary resend %d", pkt->p.data_seq);
                ubond_pkt_release(pkt);
                return;
            }
            if (aolderb(pkt->p.data_seq, l->p.data_seq))
                break;
        }
        log_debug("tcp", "Insert %d", pkt->p.data_seq);
        if (l) {
            UBOND_TAILQ_INSERT_BEFORE(&s->received, l, pkt);
        } else {
            UBOND_TAILQ_INSERT_TAIL(&s->received, pkt);
        }
    } else {
        ubond_pkt_release(pkt);
    }
    /* drain */
    int drained = 0;
    log_debug("tcp", "next_seq= %d", s->next_seq);
    while (!UBOND_TAILQ_EMPTY(&s->received) && (UBOND_TAILQ_FIRST(&s->received)->p.data_seq == s->next_seq)) {

        ubond_pkt_t* l = UBOND_TAILQ_FIRST(&s->received);
        UBOND_TAILQ_REMOVE(&s->received, l);

        s->seq_to_ack = l->p.data_seq;
        s->next_seq = s->seq_to_ack + 1;

        if (l->p.type == UBOND_PKT_TCP_CLOSE) {
            ubond_pkt_release(l);
            ubond_stream_close(s);
            return;
        }

        if (l->p.len > 0) {
            l->sent = 0;
            UBOND_TAILQ_INSERT_HEAD(&s->draining, l);

            log_debug("tcp", "drain packet %d", l->p.data_seq);
            if (!ev_is_active(&s->io_write)) {
                ev_io_start(EV_DEFAULT_ & s->io_write);
            }
            drained++;
        } else {
            ubond_pkt_release(l); 
        }
    }
    if (drained) {
        stamp(s);
    }
}

// called once the packet is sent
void tcp_sent(stream_t* s, ubond_pkt_t* pkt)
{
    UBOND_TAILQ_INSERT_TAIL(&s->sent, pkt);

    if (s->sent.length >= TCP_MAX_OUTSTANDING) {
        ev_io_stop(EV_DEFAULT_ & s->io_read);
    }

    if (s->sending > 0)
        s->sending--;
}

//send recieved packets back on the socket
// could be server or client side
static void on_write_cb(struct ev_loop* loop, struct ev_io* ev, int revents)
{
    stream_t* s = (stream_t*)ev->data;

    /* drain */
    // while?
    if (!UBOND_TAILQ_EMPTY(&s->draining)) {
        ubond_pkt_t* l = UBOND_TAILQ_LAST(&s->draining);
        ssize_t ret = write(s->fd, &(l->p.data[l->sent]), l->p.len - l->sent);
        if (ret > 0)
            l->sent += ret;
        if (ret < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                log_warn("sock", "write error: %zd/%d bytes sent (closing stream) ", ret, l->p.len);
                ubond_pkt_t* p = ubond_pkt_get();
                p->p.len = 0;
                send_pkt_tun(s, p, UBOND_PKT_TCP_CLOSE);
                ubond_stream_close(s); // is this safe? it will drain all pkts including this one
            }
            return;
        }
        if (l->sent >= l->p.len) {
            log_debug("sock", "drained %d", l->p.data_seq);
            UBOND_TAILQ_REMOVE(&s->draining, l);
            ubond_pkt_release(l);
        }
    }
    if (UBOND_TAILQ_EMPTY(&s->draining)) {
        if (ev_is_active(&s->io_write)) {
            ev_io_stop(EV_DEFAULT_ & s->io_write);
        }
    }
}

//recieve a packet and set it up to be sent
// could be server or client side
ubond_pkt_t *sock_spair=NULL;
static void on_read_cb(struct ev_loop* loop, struct ev_io* ev, int revents)
{
    stream_t* s = (stream_t*)ev->data;
    ssize_t rv;
    do {
        if (ubond_pkt_list_is_full(&send_buffer))
            break;
        if (!sock_spair) sock_spair=ubond_pkt_get();
        ubond_pkt_t* pkt = sock_spair;
        rv = recv(ev->fd, &pkt->p.data, ubond_options.mtu, MSG_DONTWAIT);
        if (rv < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                log_warn("sock", "stream closing ");
                pkt->p.len = 0;
                send_pkt_tun(s, pkt, UBOND_PKT_TCP_CLOSE);
                sock_spair=NULL;
                break;
            }
        }
        if (rv > 0) {
            pkt->p.len = rv;
            send_pkt_tun(s, pkt, UBOND_PKT_TCP_DATA);
            sock_spair=NULL;
            printf("HERE %lu\n", send_buffer.length);
        } else {
            break;
        }
    } while (0);

    if (ubond_pkt_list_is_full_watermark(&send_buffer)) {
        pause_streams();
    }
}

static void on_accept_cb(struct ev_loop* loop, struct ev_io* ev, int revents)
{
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
    ev_io_init(&stream->io_write, on_write_cb, fd, EV_WRITE);
    stream->io_read.data = (void*)stream;
    stream->io_write.data = (void*)stream;
    stream->flow_id = stream->preset_flow_id; // we set the flowID
    stream->sending = 0;
    stream->seq_to_ack = 0;
    stream->next_seq = 0;

    UBOND_TAILQ_INIT(&stream->sent);
    UBOND_TAILQ_INIT(&stream->received);
    UBOND_TAILQ_INIT(&stream->draining);

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
    pkt->p.data_seq = 0;
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

    log_debug("tcp", "New socket request");

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        log_warn("sock", "Unable to open socket ");
        return;
    }
    int r = connect(fd, rp, sizeof(struct sockaddr));
    if (r < 0) {
        log_warn("sock", "Unable to connect socket fd:%d  ip:%s port:%d",
            fd, inet_ntoa(((struct sockaddr_in*)rp)->sin_addr), ntohs(((struct sockaddr_in*)rp)->sin_port));
        close(fd);
        return;
    }

    stream_t* s;
    s = ubond_stream_get();
    s->fd = fd;
    s->flow_id = pkt->p.flow_id; // THEY set the flowid
    s->data_seq = 0;
    s->next_seq = 0;
    ev_io_init(&s->io_read, on_read_cb, fd, EV_READ);
    ev_io_init(&s->io_write, on_write_cb, fd, EV_WRITE);
    s->io_read.data = (void*)s;
    s->io_write.data = (void*)s;
    UBOND_TAILQ_INIT(&s->sent);
    UBOND_TAILQ_INIT(&s->received);
    UBOND_TAILQ_INIT(&s->draining);
    UBOND_TAILQ_INSERT_TAIL(&active, s);
    if (!paused)
        ev_io_start(EV_DEFAULT_ & s->io_read);
}
