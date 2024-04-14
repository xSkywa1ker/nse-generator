// NetworkStructures.h
#ifndef NETWORK_STRUCTURES_H
#define NETWORK_STRUCTURES_H

#include <cstdint>
#include <arpa/inet.h>
#include <vector>
#include <netinet/ether.h>

typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

typedef struct ethernet_header {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;
} ethernet_header;

typedef struct ip_header {
    u_char ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl;            // Time to live
    u_char proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address saddr;      // Source address
    ip_address daddr;      // Destination address
} ip_header;

typedef u_int32_t tcp_seq;

typedef struct arp_header {
    u_short hardware_type;     // Тип аппаратного устройства
    u_short protocol_type;     // Тип протокола
    u_char hardware_len;       // Длина аппаратного адреса
    u_char protocol_len;       // Длина протокольного адреса
    u_short opcode;            // Операционный код
    u_char sender_mac[6];     // MAC-адрес отправителя
    u_char sender_ip[4];      // IP-адрес отправителя
    u_char target_mac[6];     // MAC-адрес получателя
    u_char target_ip[4];      // IP-адрес получателя
} arp_header;

typedef struct tcp_header {
    u_short sport;          // Source port
    u_short dport;          // Destination port
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
    u_char th_flags;
    u_short th_win;        /* window */
    u_short th_sum;        /* checksum */
    u_short th_urp;        /* urgent pointer */
} tcp_header;

typedef struct udp_header {
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
} udp_header;

typedef struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequenceNumber;
} icmp_header;

#endif
