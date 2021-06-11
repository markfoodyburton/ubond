
#include "ubond.h"

#define IP4PKTMINSIZE 20

typedef struct ubond_mptcp_tunnel_s {
    ubond_tunnel_t* base;

    int fd_tcp;
    int fd_tcp_conn;
    ev_io io_accept;
    ev_io io_tcp_read;
    ev_io io_tcp_write;
    ubond_pkt_t* tcp_fill;
    ev_check tcp_r_check_ev;
    ev_check tcp_w_check_ev;
    int tcp_authenticated;
    ev_timer io_tcp_timeout;

    ubond_pkt_t* sending_tcp;
} ubond_mptcp_tunnel_t;

int ubond_mptcp_rtun_send(EV_P);
void ubond_mptcp_rtun_new(EV_P_ ubond_tunnel_t* base);
void mptcp_restart(EV_P);
