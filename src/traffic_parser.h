#include "NetworkStructures.h"

#ifndef TRAFFIC_PARSER_H
#define TRAFFIC_PARSER_H

int traffic_parser(const char* path_to_traffic);

#endif
void printIPHeader(const ip_header* ipHeader);

void printTCPHeader(const tcp_header* tcpHeader);

void printUDPHeader(const udp_header* udpHeader);
