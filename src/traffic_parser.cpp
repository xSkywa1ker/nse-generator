#include <iostream>
#include <pcap.h>
#include <cstdint>
#include "traffic_parser.h"
#include <vector>
#include "manage.h"
#include <arpa/inet.h>
#include <cstring>
#include <fstream>

std::string ip_to_char(ip_address ip);

int traffic_parser(const char *path_to_traffic, std::string ip_scanner,std::string ip_victim) {
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
            if (etherType == 0x0806) {
                std::cout << "ARP ";
                arp_header *arpHeader = (arp_header *)(packetData + 14);
                uint32_t senderIP = arpHeader->sender_ip;
                std::cout << "Sender IP: " << int_to_ip(senderIP) << std::endl;
            }
            if (etherType == 0x0800) {
                ip_header *ipHeader = (ip_header *)(packetData + 14);
                bool is_scanner = true;
                if (ip_to_char(ipHeader->saddr) == ip_scanner) {
                    std::cout << "scanner" << std::endl;
                    is_scanner = true;
                }
                else {
                    std::cout << "victim" << std::endl;
                    is_scanner = false;
                }
                if (ipHeader->proto == 6) {
                    tcp_header *tcpHeader = (tcp_header *)(packetData + 14 + ((ipHeader->ver_ihl & 0x0F) << 2));
                    std::cout << "TCP" << std::endl;
                    manager(tcpHeader, is_scanner, 6);
                } else if (ipHeader->proto == 17) {
                    udp_header *udpHeader = (udp_header *)(packetData + 14 + ((ipHeader->ver_ihl & 0x0F) * 4));
                    if (udpHeader->source == 67 || udpHeader->dest == 68) {
                        std::cout << "DHCP" << std::endl;
                        manager(dhcpHeader, is_scanner, 67);
                    } else {
                        std::cout << "UDP" << std::endl;
                        manager(udpHeader, is_scanner, 17);
                    }
                }
                else if (ipHeader->proto == 2) {
                    icmp_header *icmpHeader = (icmp_header *)(packetData + 14 + ((ipHeader->ver_ihl & 0x0F) * 4));
                    std::cout << "ICMP" << std::endl;
                    manager(icmpHeader, is_scanner, 2);
                }
            }
        }
        else {
            std::cout << "Пока что нет обработки протокола IPv6, либо неверный пакет" << std::endl;
        }
    }

    pcap_close(handle);

    // Добавьте код для создания файла script.nse с нужным содержимым
    std::ofstream scriptFile("script.nse");
    if (scriptFile.is_open()) {
        scriptFile << "description = \"Custom NSE Script for TCP results\"\n";
        scriptFile << "categories = {\"default\"}\n";
        scriptFile << "action = function ()\n";
        scriptFile << "   os.execute(\"g++ -o temp src/tcp_result.cpp -lpcap\")\n";
        scriptFile << "   os.execute(\"sleep 2\")\n";
        scriptFile << "   os.execute(\"./temp\")\n";
        scriptFile << "end\n";
        scriptFile << "portrule = function ()\n";
        scriptFile << "  return true\n";
        scriptFile << "end\n";
        scriptFile.close();
    } else {
        std::cerr << "Error creating script.nse file." << std::endl;
        return 1;
    }
    return 0;
}


std::string ip_to_char(ip_address ip)
{
    std::string res_ip;
    res_ip.append(std::to_string(ip.byte1));
    res_ip.append(".");
    res_ip.append(std::to_string(ip.byte2));
    res_ip.append(".");
    res_ip.append(std::to_string(ip.byte3));
    res_ip.append(".");
    res_ip.append(std::to_string(ip.byte4));
    std::cout << res_ip << std::endl;
    return res_ip;
}