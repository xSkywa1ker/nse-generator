#define MAX_PACKETS 100

// Глобальные переменные для хранения принятых пакетов
struct pcap_pkthdr *received_packet_headers[MAX_PACKETS];
const u_char *received_packets[MAX_PACKETS];
int num_received_packets = 0;

void send_and_receive_arp_packet(const char *interface, const char *source_ip, const char *target_ip) {
    int sockfd;
    struct sockaddr_ll socket_address;
    char packet[42];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Создание сокета
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Открытие интерфейса для прослушивания ARP пакетов
    if ((handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // Установка фильтра для принятых ARP пакетов
    struct bpf_program fp;
    char filter_exp[] = "arp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Создание ARP пакета
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ether_arp *arp_packet = (struct ether_arp *)(packet + sizeof(struct ether_header));

    memset(packet, 0, sizeof(packet));

    // Заполнение Ethernet заголовка
    memset(eth_header->ether_dhost, 0xff, ETH_ALEN); // MAC-адрес назначения (broadcast)
    memset(eth_header->ether_shost, 0x00, ETH_ALEN); // MAC-адрес источника
    eth_header->ether_type = htons(ETHERTYPE_ARP);

    // Заполнение ARP пакета
    arp_packet->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_packet->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_packet->ea_hdr.ar_hln = ETH_ALEN;
    arp_packet->ea_hdr.ar_pln = sizeof(in_addr_t);
    arp_packet->ea_hdr.ar_op = htons(ARPOP_REQUEST);

    // MAC-адрес источника
    memset(arp_packet->arp_sha, 0x00, ETH_ALEN);
    // IP-адрес источника
    inet_pton(AF_INET, source_ip, arp_packet->arp_spa);
    // MAC-адрес назначения (broadcast)
    memset(arp_packet->arp_tha, 0x00, ETH_ALEN);
    // IP-адрес назначения
    inet_pton(AF_INET, target_ip, arp_packet->arp_tpa);

    // Отправка ARP пакета
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_halen = ETH_ALEN;
    memset(socket_address.sll_addr, 0xff, ETH_ALEN);

    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&socket_address, sizeof(socket_address)) == -1) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    printf("ARP packet sent successfully!\n");

    // Получение ARP пакетов
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

void receive_arp_packet(const char *expected_source_ip, const char *expected_target_ip) {
    if (num_received_packets == 0) {
        printf("No ARP packets received.\n");
        return;
    }

    bool packetFound = false;

    for (int i = 0; i < num_received_packets; i++) {
        struct ether_header *eth_header = (struct ether_header *)received_packets[i];
        struct ether_arp *arp_packet = (struct ether_arp *)(received_packets[i] + sizeof(struct ether_header));

        char source_ip[INET_ADDRSTRLEN];
        char target_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, arp_packet->arp_spa, source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, arp_packet->arp_tpa, target_ip, INET_ADDRSTRLEN);

        if (strcmp(source_ip, expected_source_ip) == 0 && strcmp(target_ip, expected_target_ip) == 0) {
            printf("Matching packet found:\n");
            printf("Ethernet Header:\n");
            printf(" - Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth_header->ether_shost[0], eth_header->ether_shost[1],
                   eth_header->ether_shost[2], eth_header->ether_shost[3],
                   eth_header->ether_shost[4], eth_header->ether_shost[5]);
            printf(" - Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth_header->ether_dhost[0], eth_header->ether_dhost[1],
                   eth_header->ether_dhost[2], eth_header->ether_dhost[3],
                   eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
            printf("ARP Header:\n");
            printf(" - Source IP: %s\n", source_ip);
            printf(" - Target IP: %s\n", target_ip);
            printf(" - Operation: %d\n", ntohs(arp_packet->ea_hdr.ar_op));

            // Удаление пакета из массива
            for (int j = i; j < num_received_packets - 1; j++) {
                received_packet_headers[j] = received_packet_headers[j + 1];
                received_packets[j] = received_packets[j + 1];
            }
            num_received_packets--;
            packetFound = true;
            break;
        }
    }

    if (!packetFound) {
        printf("No matching packet found.\n");
    }
}

//int main() {
//    send_and_receive_arp_packet("eth0", "192.168.1.1", "192.168.1.2");
//
//    receive_arp_packet("192.168.1.1", "192.168.1.2");
//    return 0;
//}
