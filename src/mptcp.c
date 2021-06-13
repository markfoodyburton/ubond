
#include <errno.h>

#include "mptcp.h"
#include "privsep.h"

static void ubond_rtun_accept(EV_P_ ev_io* w, int revents);
static void ubond_rtun_tcp_read(EV_P_ ev_io* w, int revents);
static void ubond_rtun_tcp_write(EV_P_ ev_io* w, int revents);
static int ubond_mptcp_check_auth(EV_P_ ubond_mptcp_tunnel_t* tun, ubond_pkt_t* pkt);
static void ubond_rtun_check_tcp_timeout(EV_P_ ev_timer* w, int revents);
static void ubond_tcp_r_check(EV_P_ ev_check* w, int revents);
static void ubond_tcp_w_check(EV_P_ ev_check* w, int revents);
static void mptcp_socket_close(EV_P_ ubond_mptcp_tunnel_t* t);
static void mptcp_socket_reconnect(EV_P_ ubond_mptcp_tunnel_t* t);

ubond_pkt_list_t mptcp_buffer;
ubond_mptcp_tunnel_t* mptun = NULL;

void mptcp_restart(EV_P)
{
    mptcp_socket_close(EV_A_ mptun);
}

void ubond_mptcp_rtun_new(EV_P_ ubond_tunnel_t* base)
{
    if (mptun)
        return; // We set up ONE tunnel using the ip address of the first tunnel

    ubond_mptcp_tunnel_t* new = (ubond_mptcp_tunnel_t*)calloc(1, sizeof(ubond_mptcp_tunnel_t));
    if (!new)
        fatal(NULL, "calloc failed");

    new->base = base;

    new->fd_tcp = -1;
    new->fd_tcp_conn = -1;
    new->tcp_authenticated = 0;

    new->io_accept.data = new;
    new->io_tcp_read.data = new;
    new->io_tcp_write.data = new;
    ev_init(&new->io_tcp_read, ubond_rtun_tcp_read);
    ev_init(&new->io_tcp_write, ubond_rtun_tcp_write);
    ev_init(&new->io_accept, ubond_rtun_accept);

    ev_timer_init(&new->io_tcp_timeout, ubond_rtun_check_tcp_timeout,
        0., 1); //UBOND_IO_TIMEOUT_DEFAULT);
    new->io_tcp_timeout.data = new;
    ev_timer_start(EV_A_ & new->io_tcp_timeout);

    new->tcp_fill = NULL;
    new->tcp_r_check_ev.data = new;
    ev_check_init(&new->tcp_r_check_ev, ubond_tcp_r_check);
    new->tcp_w_check_ev.data = new;
    ev_check_init(&new->tcp_w_check_ev, ubond_tcp_w_check);
    new->sending_tcp = NULL;

    log_info("tcp", "Setup tcp tunnel (based on %s)", base->name);
    mptun = new;
}

/* TCP read */
static void ubond_rtun_tcp_read(EV_P_ ev_io* w, int revents)
{
    check_watcher(UBOND_RTUN_TCP_READ);
    ubond_mptcp_tunnel_t* tun = w->data;
    if (tun->fd_tcp < 0) {
        if (tun->tcp_fill) {
            ubond_pkt_release(tun->tcp_fill);
        }
        tun->tcp_fill = NULL;
        return;
    }
    struct sockaddr_storage clientaddr;
    socklen_t addrlen = sizeof(clientaddr);
    do {
        //            printf("READ tcp %s\n", tun->base->name);
        if (tun->tcp_fill == NULL) {
            tun->tcp_fill = ubond_pkt_get();
            tun->tcp_fill->len = 0;
            tun->tcp_fill->p.len = IP4PKTMINSIZE; // min size
            tun->tcp_fill->p.type = UBOND_PKT_DATA;
        }
        ubond_pkt_t* pkt = tun->tcp_fill;
        char* tcp_data = (char*)&(pkt->p.data);

        if (pkt->len < IP4PKTMINSIZE) {
            ssize_t len = recvfrom(tun->fd_tcp, &(tcp_data[pkt->len]),
                IP4PKTMINSIZE - pkt->len,
                MSG_DONTWAIT, (struct sockaddr*)&clientaddr, &addrlen);
            // No need to check each time the address as somebody can't 'hijack' this stream connection
            // needs to be done once after the accept
            if (len <= 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    log_warn("net", "TCP read error");
                    mptcp_socket_close(EV_A_ tun);
                    ubond_pkt_release(pkt);
                    tun->tcp_fill = NULL;
                }
                return;
            }
            if (len > 0) {
                pkt->len += len;
            }
            if (pkt->len >= IP4PKTMINSIZE) {
                pkt->p.len = htobe16(*(uint16_t*)(&pkt->p.data[2]));
            }
        }
        if (pkt->len >= IP4PKTMINSIZE) {
            ssize_t to_read = pkt->p.len - pkt->len;
            ssize_t len = (to_read) ? recvfrom(tun->fd_tcp, &(tcp_data[pkt->len]),
                                          to_read,
                                          MSG_DONTWAIT, (struct sockaddr*)&clientaddr, &addrlen)
                                    : 0;
            if (len <= 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    log_warn("net", "TCP read error");
                    mptcp_socket_close(EV_A_ tun);
                    ubond_pkt_release(pkt);
                    tun->tcp_fill = NULL;
                }
                return;
            }
            if (len > 0) {
                pkt->len += len;
            }
        }
        if (pkt->len >= IP4PKTMINSIZE && pkt->len > pkt->p.len) {
            fatalx("Packet length too large?");
        }
        if (pkt->len >= IP4PKTMINSIZE) {
            if (!use_tcp(pkt)) {
                log_warnx("tcp", "Corrupt packet pkt type : %d", pkt->p.data[9]);
                mptcp_socket_close(EV_A_ tun);
                ubond_pkt_release(pkt);
                tun->tcp_fill = NULL;
                return;
            }
        }
        if (pkt->len == pkt->p.len) {
            log_debug("tcp", "< TCP recieved from mptcp %ld bytes (fd:%d)",
                pkt->len, tun->fd_tcp);
            if (ubond_mptcp_check_auth(EV_A_ tun, pkt)) {
                ubond_rtun_inject_tuntap(pkt);
            } else {
                ubond_pkt_release(pkt);
            }
            //            ubond_rtun_read_pkt(tun, pkt);
            tun->tcp_fill = NULL;
            if (ev_is_active(&tun->tcp_r_check_ev))
                ev_check_stop(EV_A_ & tun->tcp_r_check_ev);
        } else {
            log_debug("tcp", "Need more %d", pkt->p.len - pkt->len);
            if (!ev_is_active(&tun->tcp_r_check_ev))
                ev_check_start(EV_A_ & tun->tcp_r_check_ev);
            break;
        }
    } while (0);
}

static void ubond_tcp_r_check(EV_P_ ev_check* w, int revents)
{
    check_watcher(UBOND_TCP_RW_IDLE_CHECK);
    ubond_mptcp_tunnel_t* tun = w->data;
    ev_invoke(EV_A_ & tun->io_tcp_read, revents);
}
static void ubond_tcp_w_check(EV_P_ ev_check* w, int revents)
{
    check_watcher(UBOND_TCP_RW_IDLE_CHECK);
    ubond_mptcp_tunnel_t* tun = w->data;
    ev_invoke(EV_A_ & tun->io_tcp_write, revents);
}

int ubond_mptcp_rtun_send(EV_P)
{
    ubond_mptcp_tunnel_t* tun = mptun;
    if (!tun || tun->fd_tcp <= 0)
        return 0;
    if (tun->sending_tcp)
        return 0;

    //    if (!ubond_pkt_list_is_full(&mptcp_buffer)) {
    //        start_tuntap_read();
    //        if (!ev_is_active(&tuntap.io_read)) {
    //            //            log_warnx(NULL, "starting io_read");
    //            ev_io_start(EV_A_ & tuntap.io_read);
    //        }
    //    }
    ubond_pkt_t* pkt = UBOND_TAILQ_POP_LAST(&mptcp_buffer);
    if (!ubond_pkt_list_is_full(&mptcp_buffer)) {
        start_tuntap_read();
    }
    if (!pkt) {
        if (ev_is_active(&tun->io_tcp_write)) {
            //            log_warnx("tcp", "no more writes");
            ev_io_stop(EV_A_ & tun->io_tcp_write);
        }
        return 0;
    }
    pkt->p.tun_seq = 0;
    pkt->p.timestamp = 0;
    size_t wlen = pkt->p.len;
    pkt->len = wlen;
    pkt->sent = 0;

    tun->sending_tcp = pkt;

    if (!ev_is_active(&tun->io_tcp_write)) {
        //            log_warnx("tcp", "starting writes");
        ev_io_start(EV_A_ & tun->io_tcp_write);
    }

    return 1;
}

static void ubond_rtun_tcp_write(EV_P_ ev_io* w, int revents)
{
    check_watcher(UBOND_RTUN_TCP_WRITE);

    ubond_mptcp_tunnel_t* tun = w->data;
    ubond_pkt_t* pkt = tun->sending_tcp;
    ssize_t ret = 0;
    if (pkt && pkt->sent < pkt->len) {
        char* tcp_data = (char*)&(pkt->p.data);
        ret = sendto(tun->fd_tcp, &(tcp_data[pkt->sent]), pkt->len - pkt->sent, MSG_DONTWAIT,
            tun->base->addrinfo->ai_addr, tun->base->addrinfo->ai_addrlen);
        if (ret > 0) {
            pkt->sent += ret;
        }
        if (ret <= 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                log_warn("net", "tcp write error");
                mptcp_socket_close(EV_A_ tun);
                pkt->sent = 0;
                // NB leave sending_tcp pointing at this packet
                return;
            }
        }
    }
    if (!pkt || pkt->sent >= pkt->len) {
        tun->sending_tcp = NULL;
        if (pkt) {
            ubond_pkt_release(pkt);
            log_debug("tcp", "> tcp sent all %d bytes (size=%d, type=%d, tun seq=0x%x, data seq=0x%x fd:%d)",
                pkt->len, pkt->p.len, pkt->p.type, pkt->p.tun_seq, pkt->p.data_seq, tun->fd_tcp);
            if (ev_is_active(&tun->tcp_w_check_ev))
                ev_check_stop(EV_A_ & tun->tcp_w_check_ev);
        } else {
            if (!ev_is_active(&tun->tcp_w_check_ev))
                ev_check_start(EV_A_ & tun->tcp_w_check_ev);
        }
        ubond_mptcp_rtun_send(EV_A);
    }
}

static void ubond_mptcp_authorise(EV_P_ ubond_mptcp_tunnel_t* tun)
{
    char data[] = {
        4, 7, 0, 28, //0
        0, 0, 0, 0, //4
        0, 6, 0, 0, //8
        0, 0, 0, 0, //12
        0, 0, 0, 0, //16
        0x42, 0x42, 0x42, 0x42, //20
        0, 0, 0, 0 //24
    };

    ubond_pkt_t* pkt = ubond_pkt_get();
    if (!tun->base->server_mode) {
        *(uint32_t*)(&data[24]) = htobe32(get_secret());
    }
    memcpy(&(pkt->p.data), data, 28);
    pkt->p.len = htobe16(*(uint16_t*)(&pkt->p.data[2]));
    pkt->p.type = UBOND_PKT_DATA;
    ubond_pkt_insert(&mptcp_buffer, pkt);
    ubond_mptcp_rtun_send(EV_A);
    log_warnx("tcp", "Sending Auth to TCP tunnel");
}
static int ubond_mptcp_check_auth(EV_P_ ubond_mptcp_tunnel_t* tun, ubond_pkt_t* pkt)
{
    if (pkt->p.data[1] == 7 && *(uint32_t*)(&(pkt->p.data[20])) == 0x42424242) {
        if (*(uint32_t*)(&pkt->p.data[24]) == 0) {
            log_debug("tcp", "Auth request received");
            ubond_mptcp_authorise(EV_A_ tun);
        } else {
            if (be32toh(*(uint32_t*)(&pkt->p.data[24])) != get_secret()) {
                log_warnx("tcp", "UNAUTHORISED access");
                tun->tcp_authenticated = 0;
            } else {
                log_warnx("tcp", "Authorised TCP tunnel");
                tun->tcp_authenticated = 1;
            }
        }
        return 0;
    }
    if (!tun->tcp_authenticated)
        log_warnx("tcp", "Recieved unautherised packet");
    return tun->tcp_authenticated;
}
static void ubond_rtun_accept(EV_P_ ev_io* w, int revents)
{
    check_watcher(UBOND_RTUN_ACCEPT);
    ubond_mptcp_tunnel_t* t = w->data;

    if (t->fd_tcp > 0) {
        close(t->fd_tcp);
    }
    t->fd_tcp = accept(t->fd_tcp_conn, 0, 0);
    if (t->fd_tcp > 0) {
        log_info("tcp", "TCP socket connection accepted (fd %d)", t->fd_tcp);

        log_warnx("tcp", "set mptcp options on fd %d", t->fd_tcp);
        //        priv_set_mptcp(t->fd_tcp);

        ev_io_set(&t->io_tcp_read, t->fd_tcp, EV_READ);
        ev_io_start(EV_A_ & t->io_tcp_read);
        ev_io_set(&t->io_tcp_write, t->fd_tcp, EV_WRITE);
        ev_io_start(EV_A_ & t->io_tcp_write);

        // we should not invalidate an authorised tunnel, just in case there are valid pkt's in flight
        // but we should check - which we will do
        //        t->tcp_authenticated = 0; // We're the server, demand auth !
        ubond_mptcp_authorise(EV_A_ t);
    }
}

static void
ubond_rtun_start_tcp(EV_P_ ubond_mptcp_tunnel_t* mt)
{
    ubond_tunnel_t* t = mt->base;
    if (t->server_mode) {
        if (mt->fd_tcp_conn < 0) {
            if ((mt->fd_tcp_conn = ubond_rtun_start_socket(t, SOCK_STREAM)) < 0) {
                return mptcp_socket_close(EV_A_ mt);
            }
            //    }
            if (ubond_rtun_bind(t, mt->fd_tcp_conn, SOCK_STREAM) < 0) {
                return mptcp_socket_close(EV_A_ mt);
            }
            if (listen(mt->fd_tcp_conn, 1)) {
                return mptcp_socket_close(EV_A_ mt);
            } //listen for a single tcp connection
            log_info("tcp", "tcp tunnel based on tunnel %s, socket listening on %s (port %s   UDP fd: %d TCP fd: %d)",
                t->name, t->bindaddr ? t->bindaddr : "any", t->bindport, t->fd, mt->fd_tcp_conn);
            ev_io_set(&mt->io_accept, mt->fd_tcp_conn, EV_READ);
            ev_io_start(EV_A_ & mt->io_accept);
        }
    } else {
        if (mt->fd_tcp <= 0) {
            if ((mt->fd_tcp = ubond_rtun_start_socket(t, SOCK_STREAM)) < 0) {
                return mptcp_socket_close(EV_A_ mt);
            }
        }

        log_warnx("tcp", "set mptcp options on fd %d", mt->fd_tcp);
        //set_mptcp_options(mt->fd_tcp, IPPROTO_TCP);
        priv_set_mptcp(mt->fd_tcp);

        if (ubond_rtun_bind(t, mt->fd_tcp, SOCK_STREAM) < 0) {
            return mptcp_socket_close(EV_A_ mt);
        }

        ubond_sock_set_nonblocking(mt->fd_tcp);
        if (connect(mt->fd_tcp, t->addrinfo->ai_addr, t->addrinfo->ai_addrlen)) {
            if (errno == EINPROGRESS) {
                log_warn("tcp", "tcp tunnel socket CONNECTING to %s (port %s   UDP fd: %d TCP fd: %d)",
                    t->destaddr, t->destport, t->fd, mt->fd_tcp);
            } else {
                log_info("tcp", "tcp tunnel socket CANT CONNECT to %s (port %s   UDP fd: %d TCP fd: %d)",
                    t->destaddr, t->destport, t->fd, mt->fd_tcp);
                return mptcp_socket_close(EV_A_ mt);
            }
        } else {
            log_info("tcp", "tcp tunnel socket connected to %s (port %s   UDP fd: %d TCP fd: %d)",
                t->destaddr, t->destport, t->fd, mt->fd_tcp);
        }
        ev_io_set(&mt->io_tcp_read, mt->fd_tcp, EV_READ);
        ev_io_set(&mt->io_tcp_write, mt->fd_tcp, EV_WRITE);
        ev_io_start(EV_A_ & mt->io_tcp_read);
        ev_io_start(EV_A_ & mt->io_tcp_write);

        mt->tcp_authenticated = 1; // We're the client !
        ubond_mptcp_authorise(EV_A_ mt);
    }
}

static void mptcp_socket_close(EV_P_ ubond_mptcp_tunnel_t* t)
{
    log_warnx("tcp", "Closing TCP sockets");

    //    if (ev_is_active(&t->io_accept)) {
    //        ev_io_stop(EV_A_ & t->io_accept);
    //    }
    if (ev_is_active(&t->io_tcp_read)) {
        ev_io_stop(EV_A_ & t->io_tcp_read);
    }
    if (ev_is_active(&t->io_tcp_write)) {
        ev_io_stop(EV_A_ & t->io_tcp_write);
    }
    if (t->fd_tcp > 0)
        close(t->fd_tcp);
    //    if (t->fd_tcp_conn > 0)
    //        close(t->fd_tcp_conn);
    t->fd_tcp = -1;
    //    t->fd_tcp_conn = -1;
    ubond_rtun_start_tcp(EV_A_ t);
}

static void
ubond_rtun_check_tcp_timeout(EV_P_ ev_timer* w, int revents)
{
    check_watcher(UBOND_RTUN_CHECK_TIMEOUT);
    ubond_mptcp_tunnel_t* t = w->data;
    ev_tstamp now = ev_now(EV_A);

    if (t->fd_tcp < 0) {
        ubond_rtun_start_tcp(EV_A_ t);
    } else {
        if (!t->tcp_authenticated) {
            log_debug("tcp", "TCP Not yet authorised");
            ubond_mptcp_authorise(EV_A_ t);
        }
    }
    //priv_print_mptcp(t->fd_tcp);
    //print_mptcp_opts(t->fd_tcp);
}

int print_mptcp_opts(int sockfd)
{

    log_warnx("tcp", "tcp fd %d", sockfd);
    struct mptcp_info minfo;
    struct mptcp_meta_info meta_info;
    struct tcp_info initial;
    struct tcp_info others[10]; // increase it if needed
    struct mptcp_sub_info others_info[10]; // same
    socklen_t len;

    len = sizeof(minfo);
    minfo.tcp_info_len = sizeof(struct tcp_info);
    minfo.sub_len = sizeof(others);
    minfo.meta_len = sizeof(struct mptcp_meta_info);
    minfo.meta_info = &meta_info;
    minfo.initial = &initial;
    minfo.subflows = &others;
    minfo.sub_info_len = sizeof(struct mptcp_sub_info);
    minfo.total_sub_info_len = sizeof(others_info);
    minfo.subflow_info = &others_info;

    int r;
    if (getsockopt(sockfd, IPPROTO_TCP, MPTCP_INFO, &minfo, &len)) {
        log_warn("tcp", "Cant getsockopt");
    } else {
        log_warnx("tcp", "Got info %d %d %d", minfo.sub_len, minfo.tcp_info_len, minfo.sub_len/ minfo.tcp_info_len);
        log_warnx("tcp", "bytes:%d/%d\tuna:%d\trtt:%d\t", initial.tcpi_bytes_sent, initial.tcpi_bytes_received, initial.tcpi_unacked, initial.tcpi_rtt);
        for (int i = 0; i < minfo.sub_len/ minfo.tcp_info_len; i++) {
            log_warnx("tcp", "bytes:%d/%d\tuna:%d\trtt:%d\tAddr:%s", others[i].tcpi_bytes_sent, others[i].tcpi_bytes_received, others[i].tcpi_unacked, others[i].tcpi_rtt, inet_ntoa(others_info[i].src_v4.sin_addr));
        }
    }
}

int set_mptcp_options(int sockfd, int level)
{
    log_warnx("tcp", "set mptcp options on fd %d", sockfd);
    if (sockfd != 0 && level == IPPROTO_TCP) {
        int enable = 1;
        int ret = setsockopt(sockfd, level, MPTCP_ENABLED, &enable, sizeof(enable));

        if (ret < 0) {
            fprintf(stderr, "setsockopt: MPTCP_ENABLED error %s!\n", strerror(errno));
            fflush(stderr);
            //return ret;
        }

        char pathmanager[] = "fullmesh";
        ret = setsockopt(sockfd, level, MPTCP_PATH_MANAGER, pathmanager, sizeof(pathmanager));

        if (ret < 0) {
            fprintf(stderr, "setsockopt: MPTCP_PATH_MANAGER error %s!\n", strerror(errno));
            fflush(stderr);
            return ret;
        }

        char scheduler[] = "default";
        ret = setsockopt(sockfd, level, MPTCP_SCHEDULER, scheduler, sizeof(scheduler));

        if (ret < 0) {
            fprintf(stderr, "setsockopt: MPTCP_SCHEDULER error %s!\n", strerror(errno));
            fflush(stderr);
            return ret;
        }

        int val = MPTCP_INFO_FLAG_SAVE_MASTER;
        ret = setsockopt(sockfd, level, MPTCP_INFO, &val, sizeof(val));

        if (ret < 0) {
            fprintf(stderr, "setsockopt: MPTCP_INFO error %s!\n", strerror(errno));
            fflush(stderr);
        }

        return ret;
    }

    return 0;
}
