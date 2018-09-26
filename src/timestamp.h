#ifndef UBOND_TIMESTAMP_H
#define UBOND_TIMESTAMP_H

#include <stdint.h>
#include <ev.h>


uint64_t
ubond_timestamp64(ev_tstamp now);

uint16_t
ubond_timestamp16(uint64_t now);

uint16_t
ubond_timestamp16_diff(uint16_t tsnew, uint16_t tsold);

#endif