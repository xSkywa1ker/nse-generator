#include <iostream>
#include <cstring>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

uint16_t pcap_in_cksum(unsigned short *addr, int len);
void receive_tcp_response(const char *dev, const char *filter_exp);

// Структура для Ethernet-заголовка
struct EthernetHeader {
    uint8_t dest_mac[ETH_ALEN];
    uint8_t src_mac[ETH_ALEN];
    uint16_t ethertype;
};

// Структура для IP-заголовка
struct IPHeader {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    in_addr saddr;
    in_addr daddr;
};

// Структура для TCP-заголовка
struct TCPHeader {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack;
    uint8_t doff_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

// Структура для TCP-пакета
struct TCPPacket {
    EthernetHeader ethernet_header;
    IPHeader ip_header;
    TCPHeader tcp_header;
    const char *payload = " "; // Payload
    size_t payload_size = std::strlen(payload);
};

// Функция для отправки TCP-пакета
void send_tcp_packet(std::initializer_list<uint8_t> ether_dhost,std::initializer_list<uint8_t> ether_shost,u_short ether_type,
                     u_char ver_ihl,u_char tos,u_short tlen,u_short identification, u_short flags_fo,u_char ttl,
                     u_char proto,u_short sport,u_short dport, tcp_seq th_seq,tcp_seq th_ack,u_char th_offx2,
                     u_char th_flags,u_short th_win, u_short th_urp) {
    char errbuf[PCAP_ERRBUF_SIZE];
    TCPPacket tcpPacket;
    int i = 0;
    for (auto value : ether_dhost) {
        tcpPacket.ethernet_header.dest_mac[i] = value;
        ++i;
    }

    i = 0;
    for (auto value : ether_shost) {
        tcpPacket.ethernet_header.src_mac[i] = value;
        ++i;
    }
    tcpPacket.ethernet_header.ethertype = ether_type;
    tcpPacket.ip_header.version_ihl = ver_ihl;
    tcpPacket.ip_header.tos = tos;
    tcpPacket.ip_header.tot_len = tlen;
    tcpPacket.ip_header.id = identification;
    tcpPacket.ip_header.frag_off = flags_fo;
    tcpPacket.ip_header.ttl = ttl;
    tcpPacket.ip_header.protocol = proto;
    tcpPacket.ip_header.saddr.s_addr = inet_addr("127.0.0.1");
    tcpPacket.ip_header.daddr.s_addr = inet_addr("127.0.0.1");
    tcpPacket.tcp_header.source = sport;
    tcpPacket.tcp_header.dest = dport;
    tcpPacket.tcp_header.seq = th_seq;
    tcpPacket.tcp_header.ack = th_ack;
    tcpPacket.tcp_header.doff_reserved = th_offx2;
    tcpPacket.tcp_header.flags = th_flags;
    tcpPacket.tcp_header.window = th_win;
    tcpPacket.tcp_header.urg_ptr = th_urp;

    // Заполняем IP-заголовок
    tcpPacket.ip_header.tot_len = htons(sizeof(IPHeader) + sizeof(TCPHeader) + tcpPacket.payload_size);
    std::cout << "Total len TCP: " << tcpPacket.ip_header.tot_len << std::endl;
    tcpPacket.ip_header.check = htons(pcap_in_cksum(reinterpret_cast<unsigned short *>(&tcpPacket.ip_header), sizeof(IPHeader)));
    std::cout << "IP CheckSum: " << tcpPacket.ip_header.check << std::endl;
    // Заполняем TCP-заголовок
    std::cout << "TCP DO: " << tcpPacket.tcp_header.doff_reserved << std::endl;
    tcpPacket.tcp_header.check = htons(pcap_in_cksum(reinterpret_cast<unsigned short *>(&tcpPacket.tcp_header), sizeof(TCPHeader) + tcpPacket.payload_size));
    std::cout << "TCP CheckSum: " << tcpPacket.tcp_header.check << std::endl;

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
    char filt_exp[20];
    std::sprintf(filt_exp,"host %s and tcp port %d", inet_ntoa(tcpPacket.ip_header.daddr), tcpPacket.tcp_header.dest);
    std::cout << filt_exp << std::endl;
    receive_tcp_response("lo", filt_exp);
}

void receive_tcp_response(const char *dev, const char *filter_exp) {
    std::cout << "Waiting for response..." << std::endl;
    char errbuf[PCAP_ERRBUF_SIZE];
    // Open the capture session in promiscuous mode
    pcap_t *recv_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (recv_handle == nullptr) {
        std::cerr << "Error opening pcap session for receiving: " << errbuf << std::endl;
        return;
    }

    // Set a filter to capture only relevant response packets
    struct bpf_program fp;
    if (pcap_compile(recv_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter: " << pcap_geterr(recv_handle) << std::endl;
        pcap_close(recv_handle);
        return;
    }
    if (pcap_setfilter(recv_handle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(recv_handle) << std::endl;
        pcap_close(recv_handle);
        return;
    }

    // Wait for the response packet
    struct pcap_pkthdr header;
    const uint8_t *packet;
    while (true) {
        packet = pcap_next(recv_handle, &header);
        if (packet != nullptr) {
            // Process the response packet as needed
            // You can parse the packet using the same structure used for sending
            std::cout << "Received a response packet." << std::endl;
            break;
        }
    }

    // Close the capture session
    pcap_close(recv_handle);
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
	send_tcp_packet({0x00, 0x0c, 0x29, 0xfb, 0x82, 0xca},{0x00, 0x0c, 0x29, 0xa3, 0x1e, 0x3e}, 0x08, 69, 00, 28, 19910, 64, 128, 6,52900, 139, 276054, 0, 128, 02, 61690, 00);
	send_tcp_packet({0x00, 0x0c, 0x29, 0xa3, 0x1e, 0x3e},{0x00, 0x0c, 0x29, 0xfb, 0x82, 0xca}, 0x08, 69, 00, 28, 30797, 64, 128, 6,139, 52900, 82248, 276054, 128, 18, 32, 00);
	send_tcp_packet({0x00, 0x0c, 0x29, 0xfb, 0x82, 0xca},{0x00, 0x0c, 0x29, 0xa3, 0x1e, 0x3e}, 0x08, 69, 00, 28, 20166, 64, 128, 6,52900, 139, 276054, 82248, 80, 16, 5152, 00);
	send_tcp_packet({0x00, 0x0c, 0x29, 0xfb, 0x82, 0xca},{0x00, 0x0c, 0x29, 0xa3, 0x1e, 0x3e}, 0x08, 69, 00, 28, 24262, 64, 128, 6,52900, 139, 276054, 82248, 80, 20, 00, 00);
}