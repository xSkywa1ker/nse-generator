// NetworkStructures.h
#ifndef NETWORK_STRUCTURES_H
#define NETWORK_STRUCTURES_H

#include <cstdint>
#include <arpa/inet.h>

struct IPHeader {
    uint8_t ip_vhl;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    uint32_t ip_src;
    uint32_t ip_dst;
};

struct TCPHeader {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t th_offx2;
    uint8_t th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};

struct UDPHeader {
    uint16_t uh_sport;
    uint16_t uh_dport;
    uint16_t uh_ulen;
    uint16_t uh_sum;
};

#endif
