#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

// Структура для Ethernet-заголовка
struct EthernetHeader {
    uint8_t dest_mac[6]; // Указать реальный MAC-адрес получателя
    uint8_t src_mac[6];  // Указать реальный MAC-адрес отправителя
    uint16_t ethertype;  // IPv4 Ethertype
};

// Структура для IP-заголовка
struct IPHeader {
    uint8_t version_ihl;     // IPv4, Header Length (5 words)
    uint8_t tos;             // Type of Service
    uint16_t tot_len;        // Total Length (will be filled later)
    uint16_t id;             // Identification
    uint16_t frag_off;       // Fragment Offset
    uint8_t ttl;             // Time to Live
    uint8_t protocol;        // TCP protocol
    uint16_t check;          // Checksum (will be filled later)
    struct in_addr saddr;    // Source IP Address (will be filled later)
    struct in_addr daddr;    // Destination IP Address (will be filled later)
};

// Структура для TCP-заголовка
struct TCPHeader {
    uint16_t source;         // Source Port
    uint16_t dest;           // Destination Port
    uint32_t seq;            // Sequence Number
    uint32_t ack_seq;        // Acknowledgment Number
    uint8_t doff_reserved;   // Data Offset (5 words), Reserved
    uint8_t flags;           // SYN flag
    uint16_t window;         // Window
    uint16_t check;          // Checksum (will be filled later)
    uint16_t urg_ptr;        // Urgent Pointer
};

// Структура для TCP-пакета
struct TCPPacket {
    struct EthernetHeader ethernet_header;
    struct IPHeader ip_header;
    struct TCPHeader tcp_header;
    const char *payload;     // Payload
    size_t payload_size;
};

// Функция для заполнения значений полей структур из переданного пакета
void fill_tcp_packet(struct TCPPacket *tcpPacket, const u_char *receivedPacket) {
    // Пример: Разбор Ethernet-заголовка
    memcpy(tcpPacket->ethernet_header.dest_mac, receivedPacket, 6);
    memcpy(tcpPacket->ethernet_header.src_mac, receivedPacket + 6, 6);
    tcpPacket->ethernet_header.ethertype = ntohs(*(uint16_t *)(receivedPacket + 12));

    // Пример: Разбор IP-заголовка
    tcpPacket->ip_header.version_ihl = receivedPacket[14] >> 4;
    tcpPacket->ip_header.tos = receivedPacket[15];
    tcpPacket->ip_header.tot_len = ntohs(*(uint16_t *)(receivedPacket + 16));
    tcpPacket->ip_header.id = ntohs(*(uint16_t *)(receivedPacket + 18));
    // Продолжите разбор для остальных полей IP-заголовка
}

// Функция для заполнения и записи значений полей структур в файл
void fill_values_in_file(struct TCPPacket *tcpPacket, const char *output_file) {
    FILE *file = fopen(output_file, "w");
    if (!file) {
        perror("Ошибка при открытии файла tcp_result.cpp для записи");
        exit(EXIT_FAILURE);
    }

    // Записываем dest_mac
    fprintf(file, "    {");
    for (int i = 0; i < 6; ++i) {
        fprintf(file, "%u", tcpPacket->ethernet_header.dest_mac[i]);
        if (i < 5) fprintf(file, ", ");
    }
    fprintf(file, "},\n");

    // Записываем src_mac
    fprintf(file, "    {");
    for (int i = 0; i < 6; ++i) {
        fprintf(file, "%u", tcpPacket->ethernet_header.src_mac[i]);
        if (i < 5) fprintf(file, ", ");
    }
    fprintf(file, "},\n");

    // Записываем ethertype
    fprintf(file, "    htons(%u)},\n", tcpPacket->ethernet_header.ethertype);

    // Продолжите запись для остальных полей структур

    fclose(file);
    printf("Файл %s успешно создан.\n", output_file);
}

void manager(const u_char *receivedPacket) {
    // Пример использования

    struct TCPPacket tcpPacket;
    fill_tcp_packet(&tcpPacket, receivedPacket);

    fill_values_in_file(&tcpPacket, "src/tcp_result.cpp");

}
