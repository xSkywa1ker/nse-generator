#include "NetworkStructures.h"

#ifndef TRAFFIC_PARSER_H
#define TRAFFIC_PARSER_H

int traffic_parser(const char* path_to_traffic);

#endif
void printIPHeader(const IPHeader* ipHeader);

void printTCPHeader(const TCPHeader* tcpHeader);

void printUDPHeader(const UDPHeader* udpHeader);
