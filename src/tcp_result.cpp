#include <iostream>
#include <cstring>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

uint16_t pcap_in_cksum(unsigned short *addr, int len);

// Структура для Ethernet-заголовка
struct EthernetHeader {
    uint8_t dest_mac[ETH_ALEN] = {0, 12, 41, 251, 130, 202};
    uint8_t src_mac[ETH_ALEN] = {0, 12, 41, 163, 30, 62};
    uint16_t ethertype = htons();                           // IPv4 Ethertype
};

// Структура для IP-заголовка
struct IPHeader {
    uint8_t version_ihl = ; // IPv4, Header Length (5 words)
    uint8_t tos = ;            // Type of Service
    uint16_t tot_len = ;       // Total Length (will be filled later)
    uint16_t id = htons(); // Identification
    uint16_t frag_off = ;       // Fragment Offset
    uint8_t ttl = ;           // Time to Live
    uint8_t protocol = ; // TCP protocol
    uint16_t check = ;          // Checksum (will be filled later)
    in_addr saddr = {};          // Source IP Address (will be filled later)
    in_addr daddr = {};          // Destination IP Address (will be filled later)
};

// Структура для TCP-заголовка
struct TCPHeader {
    uint16_t source = htons();   // Source Port
    uint16_t dest = htons();        // Destination Port
    uint32_t seq = htonl();          // Sequence Number
    uint32_t ack_seq = ;             // Acknowledgment Number
    uint8_t doff_reserved = (); // Data Offset (5 words), Reserved
    uint8_t flags = ;           // SYN flag
    uint16_t window = htons();   // Window
    uint16_t check = ;               // Checksum (will be filled later)
    uint16_t urg_ptr = ;             // Urgent Pointer
};

// Структура для TCP-пакета
struct TCPPacket {
    EthernetHeader ethernet_header;
    IPHeader ip_header;
    TCPHeader tcp_header;
    const char *payload = ""; // Payload
    size_t payload_size = std::strlen(payload);
};

// Функция для отправки TCP-пакета
void send_tcp_packet() {
    char errbuf[PCAP_ERRBUF_SIZE];
    TCPPacket tcpPacket;
    tcpPacket.ip_header.saddr.s_addr = inet_addr("127.0.0.1");
    tcpPacket.ip_header.daddr.s_addr = inet_addr("127.0.0.1");

    // Заполняем IP-заголовок
    tcpPacket.ip_header.tot_len = htons(sizeof(IPHeader) + sizeof(TCPHeader) + tcpPacket.payload_size);
    tcpPacket.ip_header.check = htons(pcap_in_cksum(reinterpret_cast<unsigned short *>(&tcpPacket.ip_header), sizeof(IPHeader)));

    // Заполняем TCP-заголовок
    tcpPacket.tcp_header.check = htons(pcap_in_cksum(reinterpret_cast<unsigned short *>(&tcpPacket.tcp_header), sizeof(TCPHeader) + tcpPacket.payload_size));

    // Открываем сессию pcap для отправки
    pcap_t *send_handle = pcap_open_live("lo", BUFSIZ, 0, 1000, errbuf);
    if (send_handle == nullptr) {
        std::cerr << "Ошибка при открытии сессии pcap: " << errbuf << std::endl;
        return;
    }

    // Создаем буфер для сырых данных пакета
    uint8_t buffer[sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(TCPHeader) + tcpPacket.payload_size];

    // Копируем данные Ethernet-заголовка
    std::memcpy(buffer, &tcpPacket.ethernet_header, sizeof(EthernetHeader));

    // Копируем данные IP-заголовка
    std::memcpy(buffer + sizeof(EthernetHeader), &tcpPacket.ip_header, sizeof(IPHeader));

    // Копируем данные TCP-заголовка
    std::memcpy(buffer + sizeof(EthernetHeader) + sizeof(IPHeader), &tcpPacket.tcp_header, sizeof(TCPHeader));

    // Копируем данные payload
    std::memcpy(buffer + sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(TCPHeader), tcpPacket.payload, tcpPacket.payload_size);

    // Отправляем пакет
    if (pcap_sendpacket(send_handle, buffer, sizeof(buffer)) != 0) {
        std::cerr << "Ошибка при отправке пакета: " << pcap_geterr(send_handle) << std::endl;
    }

    // Закрываем сессию pcap
    pcap_close(send_handle);
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

int main() {
    send_tcp_packet();
}
