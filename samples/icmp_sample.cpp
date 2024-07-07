#define PACKET_SIZE 64
#define ICMP_PACKET_SIZE 56
#define ICMP_DATA "Hello, ICMP!"
#define MAX_PACKETS 100
#define SIZE_ETHERNET 14

typedef struct ip_header {
    u_char ver_ihl;         // Version (4 bits) + Internet header length (4 bits)
    u_char tos;             // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl;             // Time to live
    u_char proto;           // Protocol
    u_short crc;            // Header checksum
    struct in_addr saddr;   // Source address
    struct in_addr daddr;   // Destination address
} ip_header;

typedef struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequenceNumber;
} icmp_header;

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

void send_and_receive_icmp_packet(const char *dest_ip, uint8_t icmp_type, uint8_t icmp_code, uint16_t seq, const char *data) {
    int sockfd;
    struct sockaddr_in dest_addr;
    char packet[1024];  // Увеличен размер пакета для размещения всех данных
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Создание сокета для отправки ICMP пакета
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Настройка адреса назначения
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip);

    // Открытие интерфейса для захвата пакетов
    if ((handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // Компиляция и установка фильтра для захвата ICMP пакетов
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

    // Создание и инициализация ICMP пакета
    struct icmp *icmp_packet = (struct icmp *)packet;
    memset(packet, 0, sizeof(packet));  // Обнуление пакета
    icmp_packet->icmp_type = icmp_type;
    icmp_packet->icmp_code = icmp_code;
    icmp_packet->icmp_id = htons(getpid());
    icmp_packet->icmp_seq = htons(seq);

    // Инициализация данных
    memset(packet + sizeof(struct icmp), 0, 56);  // Заполнение 56 байтов данных нулями
    if (data) {
        memcpy(packet + sizeof(struct icmp), data, strlen(data));  // Копирование реальных данных, если они есть
    }

    // Расчет контрольной суммы
    icmp_packet->icmp_cksum = 0;
    icmp_packet->icmp_cksum = calculate_checksum((unsigned short *)icmp_packet, sizeof(struct icmp) + 56);

    // Отправка пакета
    if (sendto(sockfd, packet, sizeof(struct icmp) + 56, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    printf("ICMP packet sent successfully!\n");

    // Ждем ответный пакет
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    while (1) {
        if (pcap_next_ex(handle, &header, &pkt_data) == 1) {
            received_packet_headers[num_received_packets] = header;
            received_packets[num_received_packets] = pkt_data;
            num_received_packets++;
            break; // Выход из цикла после получения одного пакета
        }
    }

    close(sockfd);
    pcap_close(handle);
}


void receive_icmp_packet(u_char expectedType, u_char expectedCode) {
    if (num_received_packets == 0) {
        printf("No ICMP packets received.\n");
        return;
    }

    bool packetFound = false;

    for (int i = 0; i < num_received_packets; i++) {
        const u_char *pkt_data = received_packets[i];
        ip_header* ip_hdr = (ip_header *)(pkt_data + SIZE_ETHERNET);
        int ip_header_length = (ip_hdr->ver_ihl & 0x0F) * 4;  // Реальная длина IP заголовка
        icmp_header* icmp_pkt = (icmp_header *)(pkt_data + SIZE_ETHERNET + ip_header_length);

        if (icmp_pkt->type == expectedType && icmp_pkt->code == expectedCode) {
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_hdr->saddr), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_hdr->daddr), dst_ip, INET_ADDRSTRLEN);

            printf("Matching packet found:\n");
            printf("IP Header:\n");
            printf(" - Source IP: %s\n", src_ip);
            printf(" - Destination IP: %s\n", dst_ip);

            printf("ICMP Header:\n");
            printf(" - Type: %d\n", icmp_pkt->type);
            printf(" - Code: %d\n", icmp_pkt->code);

            printf("ICMP Data:\n");
            printf(" - %s\n", (char *)(pkt_data + SIZE_ETHERNET + ip_header_length + sizeof(icmp_header)));

            // Removing packet from the array
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

// int main() {
//     send_and_receive_icmp_packet("192.168.91.135", ICMP_ECHO, 0);
//
//     receive_icmp_packet(ICMP_ECHO, 0);
//     return 0;
// }
