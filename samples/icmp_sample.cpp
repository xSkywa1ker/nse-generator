#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
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
        if (pcap_next_ex(handle, &header, &pkt_data) == 1) {
            // Запись принятого пакета в массив
            received_packet_headers[num_received_packets] = header;
            received_packets[num_received_packets] = pkt_data;
            num_received_packets++;
            break; // Выход из цикла после получения одного пакета
        }
    }

    // Закрытие сокета
    close(sockfd);

    // Закрытие сессии pcap
    pcap_close(handle);
}

void receive_icmp_packet() {
    if (num_received_packets == 0) {
        printf("No ICMP packets received.\n");
        return;
    }

    // Вывод полей первого пакета из массива
    struct ip *ip_header = (struct ip *)received_packets[0];
    struct icmp *icmp_packet = (struct icmp *)(received_packets[0] + (ip_header->ip_hl << 2));

    printf("IP Header:\n");
    printf(" - Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf(" - Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

    printf("ICMP Header:\n");
    printf(" - Type: %d\n", icmp_packet->icmp_type);
    printf(" - Code: %d\n", icmp_packet->icmp_code);
    printf(" - ID: %d\n", ntohs(icmp_packet->icmp_id));
    printf(" - Sequence: %d\n", ntohs(icmp_packet->icmp_seq));
    printf(" - Checksum: 0x%x\n", ntohs(icmp_packet->icmp_cksum));

    printf("ICMP Data:\n");
    printf(" - %s\n", received_packets[0] + (ip_header->ip_hl << 2) + sizeof(struct icmp));
}

int main() {
    const char *destination_ip = "127.0.0.1";

    // Отправка и получение ICMP пакетов
    send_and_receive_icmp_packet(destination_ip);
    receive_icmp_packet();

    return 0;
}
