#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <iomanip>
#include <cmath>
#include <vector>
#include <pcap.h>
#include <netinet/ip_icmp.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>  // Для использования ioctl и SIOCGIFINDEX

#define MAX_PACKET_LIFETIME 120 // Максимальное время жизни пакета в секундах
#define MAX_PACKET_SIZE 65535   // Максимальная длина пакета
#define SIZE_ETHERNET 14
#define SIZE_TCP (sizeof(tcp_header) - sizeof(u_short) - sizeof(bool))
#define SIZE_IP 20
#define SIZE_ICMP 8
#define SIZE_UDP 8
#define MAX_OPTION_SIZE 40

#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_DECLINE 4
#define DHCP_ACK 5
#define DHCP_NAK 6
#define DHCP_RELEASE 7
#define DHCP_INFORM 8

#define DHCP_OPTION_MESSAGE_TYPE 53
#define DHCP_OPTION_END 255

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
    u_short tlen;          // Total length
    u_short identification; // Identification
    u_short flags_fo;      // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl;            // Time to live
    u_char proto;          // Protocol
    u_short crc;           // Header checksum
    ip_address saddr;      // Source address
    ip_address daddr;      // Destination address
} ip_header;

typedef u_int32_t tcp_seq;

typedef struct tcp_header {
    u_short sport; // Source port
    u_short dport; // Destination port
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
    u_char th_flags;
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
    u_short mss;    // MSS option value
    u_char window_scale; // Window Scale option value
    bool sack_permitted; // SACK Permitted option
} tcp_header;

typedef struct udp_header {
    u_short sport;
    u_short dport;
    u_short len;
    u_short checksum;
} udp_header;

typedef struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequenceNumber;
} icmp_header;

typedef struct dhcp_header {
    u_char op;
    u_char htype;
    u_char hlen;
    u_char hops;
    u_int32_t xid;
    u_short secs;
    u_short flags;
    u_int32_t ciaddr;
    u_int32_t yiaddr;
    u_int32_t siaddr;
    u_int32_t giaddr;
    u_char chaddr[16];
    u_char sname[64];
    u_char file[128];
    u_char magic_cookie[4];
    u_char options[308];
} dhcp_header;

struct TemplateFlag {
    bool firstCopied = true;
    bool tcpCopied = false;
    bool udpCopied = false;
    bool icmpCopied = false;
    bool dhcpCopied = false;
    bool arpCopied = false;
};

TemplateFlag templateFlag;

struct UdpHeader {
    u_short sourcePort;
    u_short destinationPort;
    u_short length;
    u_short checksum;
};

struct ReceivedPacket {
    UdpHeader udpHeader;
    int sourcePort;
};

std::vector<ReceivedPacket> receivedPackets;

uint16_t pcap_in_cksum(unsigned short *addr, int len);
int HEX_TO_DEC(const std::string &st);

std::string var = "int main() {\n}";

void callTcp(bool isScanner, const u_char *receivedPacket, char *appData) {
    tcp_header* th = (tcp_header *)receivedPacket;
    if (isScanner) {
        std::sprintf(appData, "\tsend_tcp_packet(%d, %d, %d, %d, %d, 0x%02x);\n",
                     ntohs(th->sport),
                     ntohs(th->dport),
                     ntohl(th->th_seq),
                     ntohl(th->th_ack),
                     th->th_win, th->th_flags);
    } else {
        std::sprintf(appData, "\tlisten_tcp_packet(%d, 0x%02x);\n",
                     ntohs(th->dport), th->th_flags);
    }
}

void callUdp(bool isScanner, const u_char *receivedPacket, char *appData, const char* source_ip, const char* dest_ip) {
    ip_header* iph = (ip_header *)(receivedPacket + SIZE_ETHERNET);
    int ip_header_len = (iph->ver_ihl & 0x0F) * 4; // правильное вычисление длины IP-заголовка
    udp_header* uh = (udp_header *)(receivedPacket + SIZE_ETHERNET + ip_header_len);

    if (isScanner) {
        std::sprintf(appData, "\tsend_udp_packet(%d, %d, \"%d.%d.%d.%d\", \"%d.%d.%d.%d\", %d, \"%s\");\n",
                     ntohs(uh->sport),
                     ntohs(uh->dport),
                     iph->saddr.byte1,
                     iph->saddr.byte2,
                     iph->saddr.byte3,
                     iph->saddr.byte4,
                     iph->daddr.byte1,
                     iph->daddr.byte2,
                     iph->daddr.byte3,
                     iph->daddr.byte4,
                     ntohs(uh->len),
                     "");
    } else {
        std::sprintf(appData, "\treceive_udp_packet(%d, %d, %d, %d);\n",
                     ntohs(uh->sport),
                     ntohs(uh->dport),
                     ntohs(uh->len),
                     ntohs(uh->checksum));
    }
}

void callICMP(bool isScanner, const u_char *receivedPacket, char *appData) {
    ip_header* iph = (ip_header *)(receivedPacket + SIZE_ETHERNET);
    int ip_header_length = (iph->ver_ihl & 0x0F) * 4;  // Реальная длина IP-заголовка
    icmp_header* ih = (icmp_header *)(receivedPacket + SIZE_ETHERNET + ip_header_length);

    uint16_t seq = ntohs(ih->sequenceNumber);
    char data[64];  // Предполагаем, что данные не превышают 64 байта
    int data_len = ntohs(iph->tlen) - ip_header_length - sizeof(icmp_header);  // Вычисление длины данных

    memcpy(data, (u_char*)ih + sizeof(icmp_header), data_len);
    data[data_len] = '\0';  // Обеспечение завершения строки нулевым символом

    // Отладочный вывод
    std::cout << "IP Header Length: " << ip_header_length << " bytes" << std::endl;
    std::cout << "ICMP Data Length: " << data_len << " bytes" << std::endl;
    std::cout << "Total Length from IP Header: " << ntohs(iph->tlen) << " bytes" << std::endl;

    if (isScanner) {
        std::sprintf(appData, "\tsend_and_receive_icmp_packet(\"%d.%d.%d.%d\", %d, %d, %d, \"%s\");\n",
                     iph->daddr.byte1,
                     iph->daddr.byte2,
                     iph->daddr.byte3,
                     iph->daddr.byte4,
                     ih->type,
                     ih->code,
                     seq,
                     data);
    } else {
        std::sprintf(appData, "\treceive_icmp_packet(%d, %d);\n",
                     ih->type,
                     ih->code);
    }
}

void callDHCP(bool isScanner, const u_char *receivedPacket, char *appData) {
    // Parse IP header
    ip_header* iph = (ip_header*)(receivedPacket + SIZE_ETHERNET);
    int ip_header_len = (iph->ver_ihl & 0x0F) * 4;

    // Parse UDP header
    udp_header* udph = (udp_header*)(receivedPacket + SIZE_ETHERNET + ip_header_len);

    // Parse DHCP header
    dhcp_header* dhcph = (dhcp_header*)(receivedPacket + SIZE_ETHERNET + ip_header_len + sizeof(udp_header));

    // Extract DHCP options
    u_char* options = dhcph->options;
    u_char option_type = 0;
    u_char option_length = 0;
    u_char option_value = 0;

    for (int i = 0; i < 308;) {
        option_type = options[i++];
        if (option_type == DHCP_OPTION_END) break;
        option_length = options[i++];
        option_value = options[i];
        i += option_length;
    }

    // Convert IP addresses to strings
    char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iph->daddr, dest_ip, INET_ADDRSTRLEN);

    if (isScanner) {
        std::sprintf(appData, "\tsend_dhcp_discover(\"ens33\", \"%02x:%02x:%02x:%02x:%02x:%02x\", %u, %u, %u, %u, %u, %u, %u, %d, \"%s\", \"%s\", %u, %u, %u, %u, %u);\n",
                     dhcph->chaddr[0], dhcph->chaddr[1], dhcph->chaddr[2], dhcph->chaddr[3], dhcph->chaddr[4], dhcph->chaddr[5],
                     ntohl(dhcph->xid), ntohs(dhcph->secs), ntohs(dhcph->flags), ntohl(dhcph->ciaddr),
                     ntohl(dhcph->yiaddr), ntohl(dhcph->siaddr), ntohl(dhcph->giaddr),
                     iph->ttl, src_ip, dest_ip, ntohs(udph->sport), ntohs(udph->dport), option_type, option_length, option_value);
    } else {
        std::sprintf(appData, "\treceive_dhcp_offer(\"%s\");\n",
                     "ens33");
    }
}

void callARP(bool isScanner, const u_char *receivedPacket, char *appData) {
    const struct ethhdr* eth = (struct ethhdr*)receivedPacket;
    const struct arp_header* ah = (struct arp_header*)(receivedPacket + sizeof(struct ethhdr));
    const char* interface = "ens33";
    char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ah->sender_ip, sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, ah->target_ip, target_ip, INET_ADDRSTRLEN);

    if (isScanner) {
        snprintf(appData, 1024, "\tsend_and_receive_arp_packet(\"%s\", \"%02x:%02x:%02x:%02x:%02x:%02x\", \"%s\", \"%02x:%02x:%02x:%02x:%02x:%02x\", \"%s\");\n",
                 interface,
                 (unsigned int)ah->sender_mac[0], (unsigned int)ah->sender_mac[1],
                 (unsigned int)ah->sender_mac[2], (unsigned int)ah->sender_mac[3],
                 (unsigned int)ah->sender_mac[4], (unsigned int)ah->sender_mac[5],
                 sender_ip,
                 (unsigned int)ah->target_mac[0], (unsigned int)ah->target_mac[1],
                 (unsigned int)ah->target_mac[2], (unsigned int)ah->target_mac[3],
                 (unsigned int)ah->target_mac[4], (unsigned int)ah->target_mac[5],
                 target_ip);
    } else {
        snprintf(appData, 1024, "\tprocess_received_arp_packet(%s);\n",
                 ntohs(ah->opcode) == ARPOP_REQUEST ? "\"request\"" : "\"reply\"");
    }
}

void putMainIntoResult(const std::string &outputFile) {
    std::ofstream output(outputFile, std::ios_base::app);
    if (!output) {
        std::cerr << "Не удалось открыть файл для записи\n";
        return;
    }

    output << var;
    output.close();

    std::cout << "Программа успешно выполнена\n";
}

void fillFieldsScanner(const u_char *receivedPacket, int proto, const char* source_ip, const char* dest_ip) {
    ip_header *iph = (ip_header *)(receivedPacket + SIZE_ETHERNET);
    char appData[350];
    if (proto == 6) {
        callTcp(true, receivedPacket, appData);
    } else if (proto == 17) {
        callUdp(true, receivedPacket, appData, source_ip, dest_ip);
    } else if (proto == 67) {
        callDHCP(true, receivedPacket, appData);
    } else if (proto == 1) { // ICMP
        callICMP(true, receivedPacket, appData);
    } else if (proto == 806) { // ARP
        callARP(true, receivedPacket, appData);
    }

    // Ищем позицию закрывающей фигурной скобки
    size_t pos = var.rfind("}");

    if (pos != std::string::npos) {
        // Вставляем данные перед закрывающей фигурной скобкой
        var.insert(pos, appData);
    }
}

void fillFieldsVictim(const u_char *receivedPacket, int proto, const char* source_ip, const char* dest_ip) {
    ip_header *iph = (ip_header *)(receivedPacket + SIZE_ETHERNET);
    char appData[350];
    if (proto == 6) {
        callTcp(false, receivedPacket, appData);
    } else if (proto == 17) {
        callUdp(false, receivedPacket, appData, source_ip, dest_ip);
    } else if (proto == 67) {
        callDHCP(false, receivedPacket, appData);
    } else if (proto == 1) { // ICMP
        callICMP(false, receivedPacket, appData);
    } else if (proto == 806) { // ARP
        callARP(false, receivedPacket, appData);
    }

    // Ищем позицию закрывающей фигурной скобки
    size_t pos = var.rfind("}");

    if (pos != std::string::npos) {
        // Вставляем данные перед закрывающей фигурной скобкой
        var.insert(pos, appData);
    }
}

void fillTCPPacket(const u_char *receivedPacket) {
    ip_header* iph = (ip_header *)(receivedPacket + SIZE_ETHERNET);
    tcp_header* th = (tcp_header *)receivedPacket;
    iph->ver_ihl = (4 << 4) | (sizeof(ip_header) / 4);
    iph->tlen = htons(sizeof(ip_header) + sizeof(tcp_header));
    u_char *optionsPtr = reinterpret_cast<u_char*>(&th) + SIZE_TCP;
    int offset = (th->th_offx2 >> 4) - 5;
    iph->crc = htons(pcap_in_cksum(reinterpret_cast<unsigned short *>(&iph), sizeof(ip_header)));
    th->th_sum = htons(pcap_in_cksum(reinterpret_cast<unsigned short *>(&th), sizeof(tcp_header)));
}

void copyFileToString(const std::string& filename, std::string& content) {
    std::ifstream inputFile(filename);
    if (!inputFile) {
        std::cerr << "Не удалось открыть файл " << filename << std::endl;
        return;
    }

    std::ostringstream buffer;
    buffer << inputFile.rdbuf(); // Считываем содержимое файла в буфер
    content = buffer.str();      // Преобразуем содержимое буфера в строку
    inputFile.close();
}

void analizer(const u_char *receivedPacket, bool is_scanner, int proto, const char* source_ip, const char* dest_ip) {
    if (templateFlag.firstCopied) {
        std::ifstream inputTemplate("samples/includes.cpp");
        std::ofstream outputResult("results/result.cpp", std::ios_base::app);
        if (!inputTemplate || !outputResult) {
            std::cerr << "Не удалось открыть файл result.cpp\n";
            return;
        } else {
            std::cout << "Файлы с include успешно открыты\n";
        }
        outputResult << inputTemplate.rdbuf();
        templateFlag.firstCopied = false;
        inputTemplate.close();
        outputResult.close();
    }

    std::string outputResultContent;
    copyFileToString("results/result.cpp", outputResultContent);

    if (proto == 6) {
        if (!templateFlag.tcpCopied) {
            std::ifstream inputTemplate("samples/tcp_sample.cpp");
            std::ofstream outputResult("results/result.cpp", std::ios_base::app);
            if (!inputTemplate || !outputResult) {
                std::cerr << "Не удалось открыть файлы tcp_sample.cpp или result.cpp\n";
                return;
            }
            outputResult << "\n" << inputTemplate.rdbuf();
            templateFlag.tcpCopied = true;
            inputTemplate.close();
            outputResult.close();
        }
        fillTCPPacket(receivedPacket);
        if (is_scanner) {
            fillFieldsScanner(receivedPacket, 6, source_ip, dest_ip);
        } else {
            fillFieldsVictim(receivedPacket, 6, source_ip, dest_ip);
        }
    } else if (proto == 17) {
        if (!templateFlag.udpCopied) {
            std::ifstream inputTemplate("samples/udp_sample.cpp");
            std::ofstream outputResult("results/result.cpp", std::ios_base::app);
            if (!inputTemplate || !outputResult) {
                std::cerr << "Не удалось открыть файлы udp_sample.cpp или result.cpp\n";
                return;
            }
            outputResult << "\n" << inputTemplate.rdbuf();
            templateFlag.udpCopied = true;
            inputTemplate.close();
            outputResult.close();
        }
        if (is_scanner) {
            fillFieldsScanner(receivedPacket, 17, source_ip, dest_ip);
        } else {
            fillFieldsVictim(receivedPacket, 17, source_ip, dest_ip);
        }
    } else if (proto == 1) { // ICMP
        if (!templateFlag.icmpCopied) {
            std::ifstream inputTemplate("samples/icmp_sample.cpp");
            std::ofstream outputResult("results/result.cpp", std::ios_base::app);
            if (!inputTemplate || !outputResult) {
                std::cerr << "Не удалось открыть файлы icmp_sample.cpp или result.cpp\n";
                return;
            }
            outputResult << "\n" << inputTemplate.rdbuf();
            templateFlag.icmpCopied = true;
            inputTemplate.close();
            outputResult.close();
        }
        if (is_scanner) {
            fillFieldsScanner(receivedPacket, 1, source_ip, dest_ip);
        } else {
            fillFieldsVictim(receivedPacket, 1, source_ip, dest_ip);
        }
    } else if (proto == 806) { // ARP
        if (!templateFlag.arpCopied) {
            std::ifstream inputTemplate("samples/arp_sample.cpp");
            std::ofstream outputResult("results/result.cpp", std::ios_base::app);
            if (!inputTemplate || !outputResult) {
                std::cerr << "Не удалось открыть файлы arp_sample.cpp или result.cpp\n";
                return;
            }
            outputResult << "\n" << inputTemplate.rdbuf();
            templateFlag.arpCopied = true;
            inputTemplate.close();
            outputResult.close();
        }
        if (is_scanner) {
            fillFieldsScanner(receivedPacket, 806, source_ip, dest_ip);
        } else {
            fillFieldsVictim(receivedPacket, 806, source_ip, dest_ip);
        }
    } else if (proto == 67) {
        if (!templateFlag.dhcpCopied) {
            std::ifstream inputTemplate("samples/dhcp_sample.cpp");
            std::ofstream outputResult("results/result.cpp", std::ios_base::app);
            if (!inputTemplate || !outputResult) {
                std::cerr << "Не удалось открыть файлы dhcp_sample.cpp или result.cpp\n";
                return;
            }
            outputResult << "\n" << inputTemplate.rdbuf();
            templateFlag.dhcpCopied = true;
            inputTemplate.close();
            outputResult.close();
        }
        if (is_scanner) {
            fillFieldsScanner(receivedPacket, 67, source_ip, dest_ip);
        } else {
            fillFieldsVictim(receivedPacket, 67, source_ip, dest_ip);
        }
    }
}

// Функция для вычисления контрольной суммы
uint16_t pcap_in_cksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

int HEX_TO_DEC(const std::string &st) {
    int num = 0;
    for (char i : st) {
        if (i >= '0' && i <= '9') {
            num = num * 16 + (i - '0');
        } else if (i >= 'a' && i <= 'f') {
            num = num * 16 + (i - 'a' + 10);
        } else if (i >= 'A' && i <= 'F') {
            num = num * 16 + (i - 'A' + 10);
        }
    }
    return num;
}

