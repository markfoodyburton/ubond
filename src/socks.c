
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

#include "ubond.h"
#include "socks.h"
#include "privsep.h"

extern struct ubond_options_s ubond_options;
extern ubond_pkt_list_t send_buffer; /* send buffer */
extern ubond_pkt_list_t hpsend_buffer; /* send buffer */

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
        p->flow_id = max_flow_id++; // NB, set once, and re-used when reallocated from the pool
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

static void ubond_stream_close(stream_t* s, int final)
{
    log_warnx("sock", "Stream Closing (FD:%d)", s->fd);
    if (ev_is_active(&s->io_read)) {
        ev_io_stop(EV_DEFAULT_ & s->io_read);
    }
    close(s->fd);
    UBOND_TAILQ_REMOVE(&active, s);
    ubond_stream_release(s);

    if (UBOND_TAILQ_LENGTH(&active) >= MAXSTREAMS) {
        if (!ev_is_active(&socks_read)) {
            ev_io_start(EV_DEFAULT_ & socks_read);
        }
    }

    if (!final) {
        ubond_pkt_t* pkt = ubond_pkt_get();
        pkt->p.len = 0;
        if (s->their_flow_id)
            pkt->p.flow_id = s->their_flow_id;
        else
            pkt->p.flow_id = s->flow_id;
        pkt->p.data_seq = s->data_seq++;
        pkt->p.reorder = 1;
        pkt->p.type = UBOND_PKT_SOCK_CLOSE;
        ubond_buffer_write(&hpsend_buffer, pkt);
    }
}
int paused = 0;
void activate_streams()
{
    if (paused==0 || ubond_pkt_list_is_full(&send_buffer))
        return;
    else {
        //printf("Activate\n");
        stream_t *l;
        UBOND_TAILQ_FOREACH(l, &active)
        {
            ev_io_start(EV_DEFAULT_ &l->io_read);
        }
        paused = 0;
    }
}

void pause_streams()
{
    //printf("Pause\n");
    stream_t *l;
    UBOND_TAILQ_FOREACH(l, &active)
    {
        ev_io_stop(EV_DEFAULT_ &l->io_read);
    }
    paused = 1;
}
stream_t* find(uint32_t id)
{
    stream_t* l;
    if (!id)
        return NULL;
    UBOND_TAILQ_FOREACH(l, &active)
    {
        if (l->flow_id == id)
            return l;
    }
    return NULL;
}
int ubond_stream_write(ubond_pkt_t* pkt)
{
    stream_t *s = find(pkt->p.flow_id);
    if (!s)
        return 0;
    int ret = write(s->fd, pkt->p.data, pkt->p.len);
    if (ret != pkt->p.len) {
        log_warn("sock", "write error: %zd/%d bytes sent ", ret, pkt->p.len);
        ubond_stream_close(s, 0);
    }
    ubond_pkt_release(pkt);
    return 1;
}
static void on_read_cb(struct ev_loop* loop, struct ev_io* ev, int revents)
{
    int rv;
    char buf[DEFAULT_MTU];
    stream_t* s = (stream_t*)ev->data;
    ubond_pkt_t* pkt ;
    int read = 0;
    do
    {
        pkt = ubond_pkt_get();
        printf("fetching %d %d %d\n", ev->fd, s->fd, ubond_options.mtu);
        if (ubond_pkt_list_is_full(&send_buffer))
            break;
        rv = recv(ev->fd, &pkt->p.data, ubond_options.mtu, MSG_DONTWAIT);
        if (rv <= 0) { // ==0 is wrong? // the read>0 is a hack???
            if (read>0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                printf("Would block\n");
                break;
            } else {
                log_warn("sock", "stream closing ");
                ubond_stream_close(s, 0);
                break;
            }
        } else {
            read++;
            printf("Send packet\n");
            pkt->p.len = rv;
            pkt->p.data_seq = s->data_seq++;
            if (s->their_flow_id)
                pkt->p.flow_id = s->their_flow_id;
            else
                pkt->p.flow_id = s->flow_id;
            pkt->p.reorder = 1;

            pkt->p.type = UBOND_PKT_DATA;
            ubond_buffer_write(&send_buffer, pkt);
        }
    } while (rv > 0);
    ubond_pkt_release(pkt);

    if (ubond_pkt_list_is_full(&send_buffer)) {
        pause_streams();
    }
}

static void on_accept_cb(struct ev_loop* loop, struct ev_io* ev, int revents)
{
    stream_t *s;
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
    stream->their_flow_id = 0;

    ubond_pkt_t* pkt = ubond_pkt_get();
    if (ubond_pkt_list_is_full(&hpsend_buffer)) {
        log_warnx("sock", "Unable to proccess accept into HP send buffer");
        ubond_stream_close(stream, 1); // this is 'final', the other side hasn't even opened yet
        return;
    }

    UBOND_TAILQ_INSERT_TAIL(&active, stream);
    if (!paused) ev_io_start(EV_DEFAULT_ &stream->io_read);

    struct sockaddr* d = (struct sockaddr*)(pkt->p.data);
    *d = cliaddr;

    pkt->p.len = sizeof(struct sockaddr);
    pkt->p.flow_id = stream->flow_id;
    pkt->p.data_seq = stream->data_seq++;
    pkt->p.reorder = 1;
    pkt->p.type = UBOND_PKT_SOCK_OPEN;
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
    
    int serverfd=priv_set_socket_transparent(bindport);

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
void ubond_socks_term(ubond_pkt_t* pkt)
{
    stream_t *s = find(pkt->p.flow_id);
    if (!s) return;
    ubond_stream_close(s, 1); // this is final, the other side is asking us to terminate
}
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
    s->their_flow_id = pkt->p.flow_id;
    s->data_seq = 0;
    ev_io_init(&s->io_read, on_read_cb, fd, EV_READ);
    s->io_read.data = (void*)s;

    UBOND_TAILQ_INSERT_TAIL(&active, s);
    if (!paused) ev_io_start(EV_DEFAULT_ &s->io_read);
}
