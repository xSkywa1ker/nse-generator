#include <iostream>
#include <cstring>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>

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

struct TCPOptions {
    uint16_t mss;
    uint8_t window_scale;
    bool sack_permitted;
    // Добавьте другие опции при необходимости
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
    TCPOptions options;
};

// Структура для TCP-пакета
struct TCPPacket {
    EthernetHeader ethernet_header;
    IPHeader ip_header;
    TCPHeader tcp_header;
    const char *payload = ""; // Payload
    size_t payload_size = std::strlen(payload);
};

uint16_t calculate_ip_checksum(IPHeader *ip_header);
uint16_t calculate_tcp_checksum(IPHeader *ip_header, TCPHeader *tcp_header, const char *payload, size_t payload_size);

// Функция для отправки TCP-пакета
void send_tcp_packet(std::initializer_list<uint8_t> ether_dhost, std::initializer_list<uint8_t> ether_shost,
                     u_short ether_type, u_char ver_ihl, u_char tos, u_short tlen, u_short identification,
                     u_short flags_fo, u_char ttl, u_char proto, u_short sport, u_short dport,
                     tcp_seq th_seq, tcp_seq th_ack, u_char th_offx2, u_char th_flags, u_short th_win,
                     u_short th_urp, uint16_t th_mss, uint8_t th_window_scale, uint8_t th_sack_permitted) {
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
    tcpPacket.ip_header.saddr.s_addr = inet_addr("192.168.3.11");
    tcpPacket.ip_header.daddr.s_addr = inet_addr("192.168.3.13");
    tcpPacket.tcp_header.source = htons(sport);
    tcpPacket.tcp_header.dest = htons(dport);
    tcpPacket.tcp_header.seq = th_seq;
    tcpPacket.tcp_header.ack = th_ack;
    tcpPacket.tcp_header.doff_reserved = ((sizeof(TCPHeader) / 4) << 4) | 0;;
    tcpPacket.tcp_header.flags = th_flags;
    tcpPacket.tcp_header.window = th_win;
    tcpPacket.tcp_header.urg_ptr = th_urp;
    // Заполняем опции TCP
    tcpPacket.tcp_header.options.mss = th_mss;
    tcpPacket.tcp_header.options.window_scale = th_window_scale;
    tcpPacket.tcp_header.options.sack_permitted = th_sack_permitted;
    // Заполняем IP-заголовок
    tcpPacket.ip_header.tot_len = htons(sizeof(IPHeader) + sizeof(TCPHeader) + tcpPacket.payload_size);
    std::cout << "Total len TCP: " << tcpPacket.ip_header.tot_len << std::endl;
    tcpPacket.ip_header.check = htons(calculate_ip_checksum(&tcpPacket.ip_header));
    std::cout << "IP CheckSum: " << tcpPacket.ip_header.check << std::endl;
    // Заполняем TCP-заголовок
    std::cout << "TCP DO: " << ntohs(tcpPacket.tcp_header.doff_reserved) << std::endl;
    tcpPacket.tcp_header.check = htons(calculate_tcp_checksum(&tcpPacket.ip_header,&tcpPacket.tcp_header, tcpPacket.payload , tcpPacket.payload_size));
    std::cout << "TCP CheckSum: " << tcpPacket.tcp_header.check << std::endl;

    // Открываем сессию pcap для отправки
    pcap_t *send_handle = pcap_open_live("ens35", BUFSIZ, 0, 1000, errbuf);
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
    char filt_exp[40] = "";
    std::sprintf(filt_exp,"host %s and tcp port %d\n", inet_ntoa(tcpPacket.ip_header.daddr), ntohs(tcpPacket.tcp_header.dest));
    std::cout << filt_exp;
}

void receive_tcp_response(u_short ether_type, u_char ver_ihl, u_char tos, u_short tlen, u_short identification,
                          u_short flags_fo, u_char ttl, u_char proto, u_short sport, u_short dport,
                          tcp_seq th_seq, tcp_seq th_ack, u_char th_offx2, u_char th_flags, u_short th_win,
                          u_short th_urp) {
    std::cout << "Waiting for response..." << std::endl;
    char errbuf[PCAP_ERRBUF_SIZE];
    TCPPacket tcpPacket;
    tcpPacket.ethernet_header.ethertype = ether_type;
    tcpPacket.ip_header.version_ihl = ver_ihl;
    tcpPacket.ip_header.tos = tos;
    tcpPacket.ip_header.tot_len = tlen;
    tcpPacket.ip_header.id = identification;
    tcpPacket.ip_header.frag_off = flags_fo;
    tcpPacket.ip_header.ttl = ttl;
    tcpPacket.ip_header.protocol = proto;
    tcpPacket.ip_header.saddr.s_addr = inet_addr("192.168.3.11");
    tcpPacket.ip_header.daddr.s_addr = inet_addr("192.168.3.13");
    tcpPacket.tcp_header.source = htons(sport);
    tcpPacket.tcp_header.dest = htons(dport);
    tcpPacket.tcp_header.seq = th_seq;
    tcpPacket.tcp_header.ack = th_ack;
    tcpPacket.tcp_header.doff_reserved = ((sizeof(TCPHeader) / 4) << 4) | 0;;
    tcpPacket.tcp_header.flags = th_flags;
    tcpPacket.tcp_header.window = th_win;
    tcpPacket.tcp_header.urg_ptr = th_urp;
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

            // Extract IP header from the response packet
            IPHeader *ip_header = reinterpret_cast<IPHeader*>(packet + sizeof(EthernetHeader));

            // Compare the source IP address with the expected IP
            if (ip_header->saddr.s_addr == expected_ip.s_addr) {
                std::cout << "Received a response packet." << std::endl;
                break;
            }
        }
    }

    // Close the capture session
    pcap_close(recv_handle);
}

// Функция для вычисления контрольной суммы IP-заголовка
uint16_t calculate_ip_checksum(IPHeader *ip_header) {
    std::uint32_t sum = 0;
    std::uint16_t *addr = reinterpret_cast<std::uint16_t *>(ip_header);

    int len = sizeof(IPHeader);
    while (len > 1) {
        sum += ntohs(*addr++);
        len -= 2;
    }

    if (len == 1) {
        sum += *reinterpret_cast<std::uint8_t *>(addr);
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return static_cast<std::uint16_t>(~sum);
}

// Функция для вычисления контрольной суммы TCP-заголовка
uint16_t calculate_tcp_checksum(IPHeader *ip_header, TCPHeader *tcp_header, const char *payload, size_t payload_size) {
    uint32_t sum = 0;

    // Добавляем данные IP-псевдозаголовка
    sum += (ip_header->saddr.s_addr >> 16) + (ip_header->saddr.s_addr & 0xFFFF);
    sum += (ip_header->daddr.s_addr >> 16) + (ip_header->daddr.s_addr & 0xFFFF);
    sum += htons(IPPROTO_TCP);
    sum += htons(sizeof(TCPHeader) + payload_size);

    // Добавляем данные TCP-заголовка
    uint8_t *addr = reinterpret_cast<uint8_t *>(tcp_header);
    int len = sizeof(TCPHeader);
    while (len > 1) {
        sum += (*addr << 8) + *(addr + 1);
        addr += 2;
        len -= 2;
    }

    // Добавляем данные полезной нагрузки
    addr = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(payload));
    len = payload_size;
    while (len > 1) {
        sum += (*addr << 8) + *(addr + 1);
        addr += 2;
        len -= 2;
    }

// Добавляем последний байт, если длина нечетная
    if (len == 1) {
        sum += *addr << 8;
    }

    // Добавляем переносы
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    // Инвертируем результат
    return static_cast<uint16_t>(~sum);
}

int main() {
	send_tcp_packet({0x00, 0x0c, 0x29, 0x2d, 0x3d, 0xa6},{0x00, 0x0c, 0x29, 0xa3, 0x1e, 0x3e}, 0x08, 69, 00, 0x2c, 19910, 64, 128, 6,52900, 139, 276054, 0, 128, 02, 61690, 00, 0, 0, 0);
	//send_tcp_packet({0x00, 0x0c, 0x29, 0xa3, 0x1e, 0x3e},{0x00, 0x0c, 0x29, 0xfb, 0x82, 0xca}, 0x08, 69, 00, 0x2c, 30797, 64, 128, 6,139, 52900, 82248, 276054, 128, 18, 32, 00, 0, 0, 0);
	//send_tcp_packet({0x00, 0x0c, 0x29, 0xfb, 0x82, 0xca},{0x00, 0x0c, 0x29, 0xa3, 0x1e, 0x3e}, 0x08, 69, 00, 0x2c, 20166, 64, 128, 6,52900, 139, 276054, 82248, 80, 16, 5152, 00, 0, 0, 0);
	//send_tcp_packet({0x00, 0x0c, 0x29, 0xfb, 0x82, 0xca},{0x00, 0x0c, 0x29, 0xa3, 0x1e, 0x3e}, 0x08, 69, 00, 0x2c, 24262, 64, 128, 6,52900, 139, 276054, 82248, 80, 20, 00, 00, 0, 0, 0);
}