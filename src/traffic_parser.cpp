#include <iostream>
#include <pcap.h>
#include <cstdint>
#include "traffic_parser.h"
#include <arpa/inet.h>



void printIPHeader(const IPHeader* ipHeader) {
    std::cout << "IP Header:" << std::endl;
    std::cout << "  Source IP: " << inet_ntoa(*(in_addr*)&ipHeader->ip_src) << std::endl;
    std::cout << "  Destination IP: " << inet_ntoa(*(in_addr*)&ipHeader->ip_dst) << std::endl;
    std::cout << "  Protocol: " << static_cast<int>(ipHeader->ip_p) << std::endl;
}

void printTCPHeader(const TCPHeader* tcpHeader) {
    std::cout << "TCP Header:" << std::endl;
    std::cout << "  Source Port: " << ntohs(tcpHeader->th_sport) << std::endl;
    std::cout << "  Destination Port: " << ntohs(tcpHeader->th_dport) << std::endl;
    std::cout << "  Sequence Number: " << ntohl(tcpHeader->th_seq) << std::endl;
    std::cout << "  Acknowledgment Number: " << ntohl(tcpHeader->th_ack) << std::endl;
}

void printUDPHeader(const UDPHeader* udpHeader) {
    std::cout << "UDP Header:" << std::endl;
    std::cout << "  Source Port: " << ntohs(udpHeader->uh_sport) << std::endl;
    std::cout << "  Destination Port: " << ntohs(udpHeader->uh_dport) << std::endl;
    std::cout << "  Length: " << ntohs(udpHeader->uh_ulen) << std::endl;
}

int traffic_parser(const char* path_to_traffic) {
    const char* pcapFile = path_to_traffic;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Открываем файл pcapng для чтения
    pcap_t* handle = pcap_open_offline(pcapFile, errbuf);
    if (!handle) {
        std::cerr << "Error opening file: " << errbuf << std::endl;
        return 1;
    }

    // Начнем парсинг пакетов
    struct pcap_pkthdr header;
    const u_char* packetData;

    while ((packetData = pcap_next(handle, &header))) {
        // Проверим, что пакет содержит достаточно данных для анализа
        if (header.caplen >= 14) {
            const uint16_t etherType = (packetData[12] << 8) | packetData[13];

            if (etherType == 0x0800) {
                // Пакет IPv4
                IPHeader* ipHeader = (IPHeader*)(packetData + 14);
                printIPHeader(ipHeader);

                if (ipHeader->ip_p == 6) {
                    // Пакет TCP
                    TCPHeader* tcpHeader = (TCPHeader*)(packetData + 14 + ((ipHeader->ip_vhl & 0x0F) << 2));
                    // TODO добавить передачу пакета на вход функции manage
                    printTCPHeader(tcpHeader);
                } else if (ipHeader->ip_p == 17) {
                    // Пакет UDP
                    UDPHeader* udpHeader = (UDPHeader*)(packetData + 14 + ((ipHeader->ip_vhl & 0x0F) << 2));
                    printUDPHeader(udpHeader);
                }
            }
        }

        // TODO Добавить обработку других типов пакетов (ICMP, и т. д.)

    }

    pcap_close(handle);

    return 0;
}
