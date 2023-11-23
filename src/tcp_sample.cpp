#include <iostream>
#include <cstring>
#include <pcap.h>
#include <pcap/sll.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

uint16_t pcap_in_cksum(unsigned short *addr, int len);

// Структура для IP-заголовка
struct IPHeader {
    uint8_t version_ihl = 0x45; // IPv4, Header Length (5 words)
    uint8_t tos = 0;            // Type of Service
    uint16_t tot_len = 0;       // Total Length (will be filled later)
    uint16_t id = htons(0x1234); // Identification
    uint16_t frag_off = 0;       // Fragment Offset
    uint8_t ttl = 255;           // Time to Live
    uint8_t protocol = IPPROTO_TCP; // TCP protocol
    uint16_t check = 0;          // Checksum (will be filled later)
    in_addr saddr = {};          // Source IP Address (will be filled later)
    in_addr daddr = {};          // Destination IP Address (will be filled later)
};

// Структура для TCP-заголовка
struct TCPHeader {
    uint16_t source = htons(12345);   // Source Port
    uint16_t dest = htons(80);        // Destination Port
    uint32_t seq = htonl(1);          // Sequence Number
    uint32_t ack_seq = 0;             // Acknowledgment Number
    uint8_t doff_reserved = (5 << 4); // Data Offset (5 words), Reserved
    uint8_t flags = TH_SYN;           // SYN flag
    uint16_t window = htons(14600);   // Window
    uint16_t check = 0;               // Checksum (will be filled later)
    uint16_t urg_ptr = 0;             // Urgent Pointer
};

// Структура для TCP-пакета
struct TCPPacket {
    IPHeader ip_header;
    TCPHeader tcp_header;
    const char *payload = "Hello, World!"; // Payload
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

    // Заполняем структуру pcap_pkthdr (заголовок пакета)
    struct pcap_pkthdr packet_header;
    packet_header.ts.tv_sec = 0;
    packet_header.ts.tv_usec = 0;
    packet_header.len = sizeof(TCPPacket);
    packet_header.caplen = packet_header.len;

    // Отправляем пакет
    if (pcap_sendpacket(send_handle, reinterpret_cast<const u_char *>(&tcpPacket), packet_header.len) != 0) {
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

int main()
{
    send_tcp_packet();
}
