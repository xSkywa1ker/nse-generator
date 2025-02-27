#include <iostream>
#include <pcap.h>
#include <cstdint>
#include "traffic_parser.h"
#include <vector>
#include "manage.h"
#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include "NetworkStructures.h"

std::string ip_to_char(ip_address ip);

int traffic_parser(const char *path_to_traffic, std::string ip_scanner, std::string ip_victim) {
    const char *pcapFile = path_to_traffic;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcapFile, errbuf);
    if (!handle) {
        std::cerr << "Error opening file: " << errbuf << std::endl;
        return 1;
    }

    std::vector<std::vector<unsigned char*>> packets;  // Вектор для хранения информации о пакетах
    const char* ip_src = "192.168.91.133";
    const char* ip_dest = "192.168.91.135";
    struct pcap_pkthdr *header;
    const u_char *packetData;
    int returnValue;
    do {
        returnValue = pcap_next_ex(handle, &header, &packetData);
        if (returnValue != 1) {
            putMainIntoResult("results/result.cpp");
        }
        if (header->caplen >= 14) {
            const uint16_t etherType = (packetData[12] << 8) | packetData[13];
            if (etherType == 0x0806) {
                std::cout << "ARP ";
                arp_header *arpHeader = (arp_header *)(packetData + 14);
                char sender_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, arpHeader->sender_ip, sender_ip, INET_ADDRSTRLEN);

                bool is_scanner = false;
                if (sender_ip == ip_scanner || ip_scanner == "0") {
                    std::cout << "Scanner ARP packet" << std::endl;
                    is_scanner = true;
                } else if (sender_ip == ip_victim || ip_victim == "0") {
                    std::cout << "Victim ARP packet" << std::endl;
                    is_scanner = false;
                }
                analizer(packetData, is_scanner, 806, ip_src, ip_dest);
            }
            if (etherType == 0x0800) {
                ip_header *ipHeader = (ip_header *)(packetData + 14);
                bool is_scanner = true;
                if (ip_to_char(ipHeader->saddr) == ip_scanner || ip_scanner == "0") {
                    std::cout << "scanner" << std::endl;
                    is_scanner = true;
                } else if (ip_to_char(ipHeader->saddr) == ip_victim || ip_victim == "0") {
                    std::cout << "victim" << std::endl;
                    is_scanner = false;
                }
                if (ipHeader->proto == 6) {
                    std::cout << "TCP" << std::endl;
                    analizer(packetData, is_scanner, 6, ip_src, ip_dest);
                } else if (ipHeader->proto == 17) {
    udp_header *udpHeader = (udp_header *)(packetData + 14 + ((ipHeader->ver_ihl & 0x0F) * 4));
    uint16_t sport = ntohs(udpHeader->sport);
    uint16_t dport = ntohs(udpHeader->dport);
    if (sport == 67 || dport == 68 || sport == 68 || dport == 67) {
        std::cout << "DHCP" << std::endl;
        analizer(packetData, is_scanner, 67, ip_src, ip_dest);
    } else {
        std::cout << "UDP" << sport << std::endl;
        analizer(packetData, is_scanner, 17, ip_src, ip_dest);
    }
}
 else if (ipHeader->proto == 1) {
                    icmp_header *icmpHeader = (icmp_header *)(packetData + 14 + ((ipHeader->ver_ihl & 0x0F) * 4));
                    std::cout << "ICMP" << std::endl;
                    analizer(packetData, is_scanner, 1, ip_src, ip_dest);
                }
            }
        } else {
            std::cout << "Пока что нет обработки протокола IPv6, либо неверный пакет" << std::endl;
        }
    } while (returnValue == 1);

    pcap_close(handle);

    std::ofstream scriptFile("script.nse");
    if (scriptFile.is_open()) {
        scriptFile << "description = \"Custom NSE Script for results\"\n";
        scriptFile << "categories = {\"default\"}\n";
        scriptFile << "action = function (host, port)\n";
        scriptFile << "   os.execute(\"g++ -o temp results/result.cpp -lpcap -std=c++11\")\n";
        scriptFile << "   os.execute(\"sleep 5\")\n";
        scriptFile << "   os.execute(\"./temp\")\n";
        scriptFile << "end\n";
        scriptFile << "portrule = function (host, port)\n";
        scriptFile << "  return true\n";
        scriptFile << "end\n";
        scriptFile.close();
    } else {
        std::cerr << "Error creating script.nse file." << std::endl;
        return 1;
    }
    return 0;
}


std::string ip_to_char(ip_address ip) {
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
