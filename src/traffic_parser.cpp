#include <iostream>
#include <pcap.h>
#include <cstdint>
#include "traffic_parser.h"
#include <vector>
#include "manage.h"
#include <arpa/inet.h>

int traffic_parser(const char *path_to_traffic, const char *ip_scanner,const char *ip_victim) {
    const char *pcapFile = path_to_traffic;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcapFile, errbuf);
    if (!handle) {
        std::cerr << "Error opening file: " << errbuf << std::endl;
        return 1;
    }

    std::vector<std::vector<unsigned char*>> packets;  // Вектор для хранения информации о TCP пакетах

    struct pcap_pkthdr header;
    const u_char *packetData;

    while ((packetData = pcap_next(handle, &header))) {
        if (header.caplen >= 14) {
            const uint16_t etherType = (packetData[12] << 8) | packetData[13];
            if (etherType == 0x0800) {
                ip_header *ipHeader = (ip_header *)(packetData + 14);
                if (ipHeader->proto == 6) {
                    tcp_header *tcpHeader = (tcp_header *)(packetData + 14 + ((ipHeader->ver_ihl & 0x0F) << 2));
                    if (ipHeader->saddr == ip_scanner) {
                        manager(packetData, true);
                    }
                    else if (ipHeader->saddr == ip_victim){
                        manager(packetData, false);
                    }
                } else if (ipHeader->proto == 17) {
                    udp_header *udpHeader = (udp_header *)(packetData + 14 + ((ipHeader->ver_ihl & 0x0F) << 2));
                }
            }
        }
    }

    pcap_close(handle);


    return 0;
}
