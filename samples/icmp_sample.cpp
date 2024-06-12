#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <pcap.h>

#define PACKET_SIZE 64
#define ICMP_PACKET_SIZE 56
#define ICMP_DATA "Hello, ICMP!"
#define MAX_PACKETS 100

// Глобальные переменные для хранения принятых пакетов
struct pcap_pkthdr *received_packet_headers[MAX_PACKETS];
const u_char *received_packets[MAX_PACKETS];
int num_received_packets = 0;

unsigned short calculate_checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void send_and_receive_icmp_packet(const char *dest_ip) {
    int sockfd;
    struct sockaddr_in dest_addr;
    char packet[PACKET_SIZE];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Создание сокета
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Заполнение адреса назначения
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip);

    // Открытие интерфейса для прослушивания ICMP пакетов
    if ((handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // Установка фильтра для принятых ICMP пакетов
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Создание ICMP пакета
    struct icmp *icmp_packet = (struct icmp *)packet;
    memset(packet, 0, PACKET_SIZE);
    icmp_packet->icmp_type = ICMP_ECHO;
    icmp_packet->icmp_code = 0;
    icmp_packet->icmp_id = htons(getpid());
    icmp_packet->icmp_seq = htons(1);
    memcpy(packet + sizeof(struct icmp), ICMP_DATA, strlen(ICMP_DATA));
    icmp_packet->icmp_cksum = 0; // Обнуляем контрольную сумму перед подсчетом
    icmp_packet->icmp_cksum = calculate_checksum((unsigned short *)icmp_packet, ICMP_PACKET_SIZE);

    // Отправка ICMP пакета
    if (sendto(sockfd, packet, ICMP_PACKET_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    printf("ICMP packet sent successfully!\n");

    // Получение ICMP пакетов
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    while (1) {
        int res = pcap_next_ex(handle, &header, &pkt_data);
        if (res == 1) {
            received_packet_headers[num_received_packets] = header;
            received_packets[num_received_packets] = pkt_data;
            num_received_packets++;
            break;
        } else if (res == 0) {
            continue;
        } else {
            fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(handle));
            break;
        }
    }

    close(sockfd);

    pcap_close(handle);
}

void receive_icmp_packet(uint8_t expected_type, uint8_t expected_code, uint16_t expected_id, uint16_t expected_seq) {
    if (num_received_packets == 0) {
        printf("No ICMP packets received.\n");
        return;
    }

    // Извлечение заголовков Ethernet и IP
    struct ether_header *eth_header = (struct ether_header *)received_packets[0];
    struct ip *ip_header = (struct ip *)(received_packets[0] + sizeof(struct ether_header));
    int ip_header_length = ip_header->ip_hl << 2;

    // Извлечение заголовка ICMP
    struct icmp *icmp_packet = (struct icmp *)(received_packets[0] + sizeof(struct ether_header) + ip_header_length);

    printf("Ethernet Header:\n");
    printf(" - Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
           eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf(" - Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
           eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    printf(" - Ether Type: %04x\n", ntohs(eth_header->ether_type));

    printf("IP Header:\n");
    printf(" - Version: %d\n", ip_header->ip_v);
    printf(" - Header Length: %d bytes\n", ip_header->ip_hl * 4);
    printf(" - Type of Service: %d\n", ip_header->ip_tos);
    printf(" - Total Length: %d bytes\n", ntohs(ip_header->ip_len));
    printf(" - Identification: %d\n", ntohs(ip_header->ip_id));
    printf(" - Fragment Offset: %d\n", ntohs(ip_header->ip_off));
    printf(" - Time to Live: %d\n", ip_header->ip_ttl);
    printf(" - Protocol: %d\n", ip_header->ip_p);
    printf(" - Header Checksum: 0x%x\n", ntohs(ip_header->ip_sum));
    printf(" - Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf(" - Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

    printf("ICMP Header:\n");
    printf(" - Type: %d\n", icmp_packet->icmp_type);
    printf(" - Code: %d\n", icmp_packet->icmp_code);
    printf(" - ID: %d\n", ntohs(icmp_packet->icmp_id));
    printf(" - Sequence: %d\n", ntohs(icmp_packet->icmp_seq));
    printf(" - Checksum: 0x%x\n", ntohs(icmp_packet->icmp_cksum));

    printf("ICMP Data:\n");
    printf(" - %s\n", (char *)(received_packets[0] + sizeof(struct ether_header) + ip_header_length + sizeof(struct icmp)));

    // Сравнение принятых значений с ожидаемыми
    if (icmp_packet->icmp_type == expected_type &&
        icmp_packet->icmp_code == expected_code &&
        ntohs(icmp_packet->icmp_id) == expected_id &&
        ntohs(icmp_packet->icmp_seq) == expected_seq) {
        printf("Received ICMP packet matches the expected values.\n");
    } else {
        printf("Received ICMP packet does not match the expected values.\n");
    }
}


int main() {
    const char *dest_ip = "192.168.91.135"; // Пример IP адреса
    send_and_receive_icmp_packet(dest_ip);

    // Вызов функции receive_icmp_packet с ожидаемыми значениями
    uint8_t expected_type = ICMP_ECHO; // Тип ICMP пакета (Echo Request)
    uint8_t expected_code = 0;         // Код ICMP пакета
    uint16_t expected_id = getpid();   // ID ICMP пакета (process ID)
    uint16_t expected_seq = 1;         // Порядковый номер ICMP пакета

    receive_icmp_packet(expected_type, expected_code, expected_id, expected_seq);
    return 0;
}
