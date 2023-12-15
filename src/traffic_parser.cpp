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
            if (etherType == 0x0800) {
                ip_header *ipHeader = (ip_header *)(packetData + 14);
                if (ipHeader->proto == 6) {
                    tcp_header *tcpHeader = (tcp_header *)(packetData + 14 + ((ipHeader->ver_ihl & 0x0F) << 2));
                    std::cout << "TCP" << std::endl;
                    if (ip_to_char(ipHeader->saddr) == ip_scanner) {
                        std::cout << "scanner" << std::endl;
                        manager(packetData, true);
                    }
                    else if (ip_to_char(ipHeader->saddr) == ip_victim){
                        std::cout << "victim" << std::endl;
                        manager(packetData, false);
                    }
                } else if (ipHeader->proto == 17) {
                    udp_header *udpHeader = (udp_header *)(packetData + 14 + ((ipHeader->ver_ihl & 0x0F) << 2));
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
        scriptFile << "os.execute(\"g++ -o temp src/tcp_result.cpp -lpcap\")\n";
        scriptFile << "os.execute(\"sleep 2\")\n";
        scriptFile << "os.execute(\"./temp\")\n";
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