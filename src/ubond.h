#ifndef _UBOND_H
#define _UBOND_H

#include "includes.h"

#include <ev.h>
#include <math.h>
#include <netinet/in.h>
//#include <netinet/tcp.h>
#include <linux/tcp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* Many thanks Fabien Dupont! */
#ifdef HAVE_LINUX

#define TCP

/* Absolutely essential to have it there for IFNAMSIZ */
#include <linux/if.h>
#include <netdb.h>
#include <sys/types.h>
#endif

#include <arpa/inet.h>

#ifdef HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#else
#define RUNNING_ON_VALGRIND 0
#endif

#ifdef HAVE_DECL_RES_INIT
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>
#endif

#ifdef HAVE_FILTERS
#include <pcap/pcap.h>
#endif

#include "pkt.h"
#include "timestamp.h"

#define UBOND_MAXHNAMSTR 256
#define UBOND_MAXPORTSTR 6

/* Number of packets in the queue. Each pkt is ~ 1520 */
/* 1520 * 128 ~= 24 KBytes of data maximum per channel VMSize */
#define PKTBUFSIZE 1024
#define RESENDBUFSIZE 10240

/* tuntap interface name size */
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
#define UBOND_IFNAMSIZ IFNAMSIZ

#define MAX_TUNS 16 // maximum tunnels we can handle

/* How frequently we check tunnels */
#define UBOND_IO_TIMEOUT_DEFAULT 0.25
/* What is the maximum retry timeout */
#define UBOND_IO_TIMEOUT_MAXIMUM 60.0
/* In case we can't open the tunnel, retry every time with previous
 * timeout multiplied by the increment.
 * Example:
 * 1st try t+0: bind error
 * 2nd try t+1: bind error
 * 3rd try t+2: bind error
 * 4rd try t+4: dns error
 * ...
 * n try t+60
 * n+1 try t+60
 */
#define UBOND_IO_TIMEOUT_INCREMENT 2

/* Protocol version of ubond
 * version 0: ubond 2.0 to 2.1 
 * version 1: ubond 2.2+ (add reorder field in ubond_proto_t)
 * version 2: no longer sent on the packet, but on the auth, and structure chabged!
 */
#define UBOND_PROTOCOL_VERSION 2

struct ubond_options_s {
    /* use ps_status or not ? */
    int change_process_title;
    /* process name if set */
    char process_name[1024];
    /* where is the config file */
    char control_unix_path[MAXPATHLEN];
    char control_bind_host[UBOND_MAXHNAMSTR];
    char control_bind_port[UBOND_MAXHNAMSTR];
    char config_path[MAXPATHLEN];
    /* tunnel configuration for the status command script */
    char ip4[24];
    char ip6[128]; /* Should not exceed 45 + 3 + 1 bytes */
    char ip4_gateway[16];
    char ip6_gateway[128];
    char ip4_routes[4096]; /* Allow about 200 routes minimum */
    char ip6_routes[8192]; /* Allow about 80 routes minimum */
    int mtu;
    int config_fd;
    /* log verbosity */
    int verbose;
    int debug;
    /* User change if running as root */
    char unpriv_user[128];
    char password[128];
    int static_tunnel;
    int root_allowed;
    uint32_t reorder_buffer_size;
    uint32_t fallback_available;
    //    uint32_t tcp_socket;
};

struct ubond_status_s {
    int fallback_mode;
    int connected;
    int initialized;
    time_t start_time;
    time_t last_reload;
};

enum chap_status {
    UBOND_DISCONNECTED,
    UBOND_AUTHSENT,
    UBOND_AUTHOK,
    UBOND_LOSSY
};

typedef struct ubond_tunnel_s {
    LIST_ENTRY(ubond_tunnel_s)
    entries;
    char* name; /* tunnel name */
    char bindaddr[UBOND_MAXHNAMSTR]; /* packets source */
    char bindport[UBOND_MAXPORTSTR]; /* packets port source (or NULL) */
    char binddev[UBOND_IFNAMSIZ]; /* bind to specific device */
    uint32_t bindfib; /* FIB number to use */
    char destaddr[UBOND_MAXHNAMSTR]; /* remote server ip (can be hostname) */
    char destport[UBOND_MAXPORTSTR]; /* remote server port */
    uint16_t id; /* Unique ID which will be shared between tunnel end
                             points (e.g. port number) */
    int fd; /* socket file descriptor */
    int num; /* tunnel number on this host */

    int server_mode; /* server or client */
    int disconnects; /* is it stable ? */
    int fallback_only; /* if set, this link will be used when all others are down */
    uint64_t pkts_cnt;
    uint8_t sent_loss; /* loss as reported by far end */
    int loss; /* our average loss must be less than 256!*/
    int loss_d;
    int loss_c;
    uint16_t seq;
    uint64_t saved_timestamp;
    uint64_t saved_timestamp_received_at;
    uint16_t seq_last;
    uint64_t seq_vect;
    int reorder_length;
    double srtt_av;
    double srtt;
    double srtt_d;
    double srtt_c;
    double srtt_min;
    double srtt_reductions;
    double weight; /* For weight round robin */
    uint32_t flow_id;
    uint64_t sentpackets; /* 64bit packets sent counter */
    uint64_t recvpackets; /* 64bit packets recv counter */
    uint64_t sentbytes; /* 64bit bytes sent counter */
    uint64_t recvbytes; /* 64bit bytes recv counter */
    int64_t permitted; /* how many bytes we can send */
    uint32_t quota; /* how many bytes per second we can send */
    uint32_t timeout; /* configured timeout in seconds */
    uint64_t bandwidth_max; /* max bandwidth in bytes per second */
    //uint64_t bandwidth;   /* current bandwidth in bytes per second */
    int autobw;
    uint64_t bandwidth_measured;
    uint64_t bm_data;
    uint64_t bandwidth_out;
    ubond_pkt_list_t sbuf; /* send buffer */
    ubond_pkt_list_t hpsbuf; /* high priority buffer */
    struct addrinfo* addrinfo;
    enum chap_status status; /* Auth status */
    ev_tstamp last_activity;
    ev_io io_read;
    ev_io io_write;
    ev_timer io_timeout;
    ev_check check_ev;
    ev_idle idle_ev;

    ev_timer send_timer;
    ev_tstamp last_adjust;
    uint64_t bytes_since_adjust;
    double bytes_per_sec;
    int lossless;
    int busy_writing;

    ubond_pkt_t* sending;
    ubond_pkt_t* sending_tcp;
#ifdef RESEND
    ubond_pkt_t* old_pkts[RESENDBUFSIZE];
#endif

} ubond_tunnel_t;

#ifdef HAVE_FILTERS
struct ubond_filters_s {
    uint8_t count;
    struct bpf_program filter[255];
    ubond_tunnel_t* tun[255];
};
#endif

int ubond_config(int config_file_fd, int first_time);
int ubond_sock_set_nonblocking(int fd);

int ubond_loss_ratio(ubond_tunnel_t* tun);
void ubond_rtun_set_weight(ubond_tunnel_t* t, double weight);

ubond_tunnel_t* ubond_rtun_new(const char* name,
    const char* bindaddr, const char* bindport, const char* binddev, uint32_t bindfib,
    const char* destaddr, const char* destport,
    int server_mode, uint32_t timeout,
    int fallback_only, uint32_t bandwidth, uint32_t quota);
void ubond_rtun_drop(ubond_tunnel_t* t);
void ubond_rtun_status_down(ubond_tunnel_t* t);
#ifdef HAVE_FILTERS
int ubond_filters_add(const struct bpf_program* filter, ubond_tunnel_t* tun);
ubond_tunnel_t* ubond_filters_choose(uint32_t pktlen, const u_char* pktdata);
//void ubond_send_buffer_write(ubond_pkt_t *p);
#endif

void ubond_buffer_write(ubond_pkt_list_t* buffer, ubond_pkt_t* p);
int ubond_pkt_list_is_full(ubond_pkt_list_t* list);
int ubond_pkt_list_is_full_watermark(ubond_pkt_list_t* list);
int use_tcp(ubond_pkt_t* pkt);
void ubond_rtun_inject_tuntap(ubond_pkt_t* pkt);
uint64_t get_secret();
void start_tuntap_read();
int ubond_rtun_start_socket(ubond_tunnel_t* t, int socktype);
int ubond_rtun_bind(ubond_tunnel_t* t, int fd, int socktype);

enum checker_id {
    NO_CHECKER,
    UBOND_RESET_PERM,
    UBOND_RTUN_TCP_READ,
    UBOND_RTUN_READ,
    UBOND_RTUN_WRITE,
    UBOND_RTUN_READ_IDLE,
    UBOND_RTUN_TCP_WRITE,
    UBOND_RTUN_WRITE_TIMEOUT,
    UBOND_RTUN_WRITE_CHECK,
    UBOND_RTUN_ACCEPT,
    UBOND_CALC_BANDWIDTH,
    UBOND_RTUN_CHECK_TIMEOUT,
    TUNTAP_IO_EVENT,
    UBOND_CONFIG_RELOAD,
    UBOND_QUIT,
    UBOND_REORDER_TICK,
    //    SOCKS_ON_READ_CB,
    //    SOCKS_ON_WRITE_CB,
    //    SOCKS_ON_ACCEPT_CB,
    //    SOCKS_RESEND_TIMER,
    UBOND_TCP_RW_IDLE_CHECK,
    MAX_CHECKERS
};
#undef PROF_WATCH
#ifdef PROF_WATCH
void check_watcher(enum checker_id name);
#else
inline void check_watcher(enum checker_id name)
{
}
#endif

#include "log.h"
#include "privsep.h"
#include "reorder.h"

#endif
