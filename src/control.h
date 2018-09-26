#ifndef UBOND_CONTROL_H
#define UBOND_CONTROL_H

#include <ev.h>

#define UBOND_CTRL_EOF 0x04
#define UBOND_CTRL_TERMINATOR '\n'
/* Control socket (mkfifo and/or AF_INET6?) */
#define UBOND_CTRL_BUFSIZ 1024
/* Control timeout in seconds */
#define UBOND_CTRL_TIMEOUT 5
struct ubond_control
{
    int mode;
    /* TODO: PATHMAX */
    char fifo_path[1024];
    mode_t fifo_mode;
    int fifofd;
    char *bindaddr;
    char *bindport;
    int sockfd;
    /* Client part */
    int clientfd; /* Only supports one client for now */
    time_t last_activity;
    char rbuf[UBOND_CTRL_BUFSIZ];
    int rbufpos;
    char *wbuf;
    int wbuflen;
    int wbufpos;
    int http; /* HTTP mode ? 1 for inet socket */
    int close_after_write;
    ev_io fifo_watcher;
    ev_io sock_watcher;
    ev_io client_io_read;
    ev_io client_io_write;
    ev_timer timeout_watcher;
};

enum {
    UBOND_CONTROL_DISABLED,
    UBOND_CONTROL_READONLY,
    UBOND_CONTROL_READWRITE
};

void
ubond_control_init(struct ubond_control *ctrl);

int
ubond_control_accept(struct ubond_control *ctrl, int fd);

int
ubond_control_timeout(struct ubond_control *ctrl);

void
ubond_control_parse(struct ubond_control *ctrl, char *line);

int
ubond_control_read_check(struct ubond_control *ctrl);

/* inside control, write to buffer */
int
ubond_control_write(struct ubond_control *ctrl, void *buf, size_t len);

/* From main loop */
int
ubond_control_read(struct ubond_control *ctrl);

/* From main loop */
int
ubond_control_send(struct ubond_control *ctrl);

#endif
