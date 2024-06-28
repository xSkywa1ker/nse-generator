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

int traffic_parser(const char *path_to_traffic, std::string ip_scanner,std::string ip_victim) {
    const char *pcapFile = path_to_traffic;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcapFile, errbuf);
    if (!handle) {
        std::cerr << "Error opening file: " << errbuf << std::endl;
        return 1;
    }

    std::vector<std::vector<unsigned char*>> packets;  // Вектор для хранения информации о пакетах

    struct pcap_pkthdr *header;
    const u_char *packetData;
    int returnValue;
    do {
        returnValue = pcap_next_ex(handle, &header, &packetData);
        if(returnValue != 1){
            putMainIntoResult("results/result.cpp");
        }
        if (header->caplen >= 14) {
            const uint16_t etherType = (packetData[12] << 8) | packetData[13];
            if (etherType == 0x0806) {
                std::cout << "ARP ";
                arp_header *arpHeader = (arp_header *)(packetData + 14);
            }
            if (etherType == 0x0800) {
                ip_header *ipHeader = (ip_header *)(packetData + 14);
                bool is_scanner = true;
                if (ip_to_char(ipHeader->saddr) == ip_scanner || ip_scanner == "0") {
                    std::cout << "scanner" << std::endl;
                    is_scanner = true;
                }
                else if (ip_to_char(ipHeader->saddr) == ip_victim || ip_victim == "0"){
                    std::cout << "victim" << std::endl;
                    is_scanner = false;
                }
                if (ipHeader->proto == 6) {
                    std::cout << "TCP" << std::endl;
                    analizer(packetData, is_scanner, 6);
                } else if (ipHeader->proto == 17) {
                    udp_header *udpHeader = (udp_header *)(packetData + 14 + ((ipHeader->ver_ihl & 0x0F) * 4));
                    if (udpHeader->sport == 67 || udpHeader->dport == 68) {
                        std::cout << "DHCP" << std::endl;
                        analizer(packetData, is_scanner, 67);
                    } else {
                        std::cout << "UDP" << std::endl;
                        analizer(packetData, is_scanner, 17);
                    }
                }
                else if (ipHeader->proto == 1) {
                    icmp_header *icmpHeader = (icmp_header *)(packetData + 14 + ((ipHeader->ver_ihl & 0x0F) * 4));
                    std::cout << "ICMP" << std::endl;
                    analizer(packetData, is_scanner, 1);
                }
            }
        }
        else {
            std::cout << "Пока что нет обработки протокола IPv6, либо неверный пакет" << std::endl;
        }
    } while (returnValue == 1);

    pcap_close(handle);

    std::ofstream scriptFile("script.nse");
    if (scriptFile.is_open()) {
        scriptFile << "description = \"Custom NSE Script for TCP results\"\n";
        scriptFile << "categories = {\"default\"}\n";
        scriptFile << "action = function ()\n";
        scriptFile << "   os.execute(\"g++ -o temp src/result.cpp -lpcap\")\n";
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