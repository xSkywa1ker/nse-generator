#include <iostream>
#include <vector>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/udp.h>

#define MAX_PACKETS 100

// Структура для DHCP заголовка
struct DhcpHeader {
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
};

// Структура для DHCP опции
struct DhcpOption {
    u_char code;
    u_char length;
    u_char data[256];
};

// Структура для полученного DHCP пакета
struct ReceivedDhcpPacket {
    DhcpHeader dhcpHeader;
    std::vector<DhcpOption> options;
};

std::vector<ReceivedDhcpPacket> receivedDhcpPackets;

// Функция для отправки и получения DHCP пакетов
void send_dhcp_packet(const char* interface, const char* source_mac, const char* source_ip, const char* target_mac, const char* target_ip,
                      u_int32_t transaction_id, u_short secs, u_short flags, u_int32_t client_ip, u_int32_t your_ip,
                      u_int32_t server_ip, u_int32_t gateway_ip, const char* client_mac, const char* server_name,
                      const char* filename) {
    // Создание сокета для отправки и получения пакетов
    int clientSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (clientSocket < 0) {
        perror("Error creating socket");
        return;
    }

    // Заполнение DHCP заголовка
    DhcpHeader dhcpHeader;
    dhcpHeader.op = 1; // Операция: Запрос
    dhcpHeader.htype = 1; // Тип аппаратного устройства: Ethernet
    dhcpHeader.hlen = 6; // Длина аппаратного адреса: 6 байт (MAC-адрес)
    dhcpHeader.xid = htonl(transaction_id); // Идентификатор транзакции
    dhcpHeader.secs = htons(secs); // Время, прошедшее с начала процесса запроса (в секундах)
    dhcpHeader.flags = htons(flags); // Флаги
    dhcpHeader.ciaddr = htonl(client_ip); // IP адрес клиента
    dhcpHeader.yiaddr = htonl(your_ip); // Предложенный IP адрес
    dhcpHeader.siaddr = htonl(server_ip); // IP адрес DHCP сервера
    dhcpHeader.giaddr = htonl(gateway_ip); // IP адрес шлюза
    // Заполнение других полей DHCP заголовка в соответствии с переданными значениями
    memcpy(dhcpHeader.chaddr, client_mac, 6); // MAC адрес клиента
    strncpy(reinterpret_cast<char*>(dhcpHeader.sname), server_name, sizeof(dhcpHeader.sname)); // Имя сервера
    strncpy(reinterpret_cast<char*>(dhcpHeader.file), filename, sizeof(dhcpHeader.file)); // Имя файла

    // Создание буфера для хранения DHCP пакета
    char buffer[sizeof(DhcpHeader)];
    memcpy(buffer, &dhcpHeader, sizeof(DhcpHeader));

    // Установка параметров сокета
    struct sockaddr addr;
    memset(&addr, 0, sizeof(addr));
    strcpy(addr.sa_data, interface);

    // Отправка DHCP пакета
    sendto(clientSocket, buffer, sizeof(buffer), 0, &addr, sizeof(addr));

    // Получение DHCP пакетов
    char receivedBuffer[2048];
    while (receivedDhcpPackets.size() < MAX_PACKETS) {
        int bytesReceived = recvfrom(clientSocket, receivedBuffer, sizeof(receivedBuffer), 0, NULL, NULL);
        if (bytesReceived > 0) {
            // Приведение полученного буфера к структуре DHCP заголовка и опций
            ReceivedDhcpPacket receivedDhcpPacket;
            memcpy(&receivedDhcpPacket.dhcpHeader, receivedBuffer, sizeof(DhcpHeader));
            // Дополнительная обработка для получения опций DHCP
            // Пример добавления опции в вектор
            int offset = sizeof(DhcpHeader);
            while (offset < bytesReceived) {
                DhcpOption option;
                option.code = receivedBuffer[offset++];
                if (option.code == 0xff) break; // Конец списка опций
                option.length = receivedBuffer[offset++];
                memcpy(option.data, receivedBuffer + offset, option.length);
                offset += option.length;
                receivedDhcpPacket.options.push_back(option);
            }
            receivedDhcpPackets.push_back(receivedDhcpPacket);
        }
    }

    close(clientSocket);
}

// Функция для приема и сравнения DHCP пакетов
void receive_dhcp_packet(u_int32_t expected_xid, u_short expected_secs, u_short expected_flags, u_int32_t expected_ciaddr,
                         u_int32_t expected_yiaddr, u_int32_t expected_siaddr, u_int32_t expected_giaddr, const char* expected_chaddr,
                         const char* expected_sname, const char* expected_file) {
    if (receivedDhcpPackets.empty()) {
        printf("No DHCP packets received.\n");
        return;
    }

    bool packetFound = false;

    for (auto it = receivedDhcpPackets.begin(); it != receivedDhcpPackets.end(); ++it) {
        DhcpHeader& header = it->dhcpHeader;

        if (header.xid == expected_xid &&
            header.secs == expected_secs &&
            header.flags == expected_flags &&
            header.ciaddr == expected_ciaddr &&
            header.yiaddr == expected_yiaddr &&
            header.siaddr == expected_siaddr &&
            header.giaddr == expected_giaddr &&
            memcmp(header.chaddr, expected_chaddr, 6) == 0 &&
            strncmp(reinterpret_cast<char*>(header.sname), expected_sname, sizeof(header.sname)) == 0 &&
            strncmp(reinterpret_cast<char*>(header.file), expected_file, sizeof(header.file)) == 0) {

            printf("Matching packet found:\n");
            printf("DHCP Header:\n");
            printf(" - Transaction ID: %u\n", ntohl(header.xid));
            printf(" - Seconds: %u\n", ntohs(header.secs));
            printf(" - Flags: %u\n", ntohs(header.flags));
            printf(" - Client IP: %s\n", inet_ntoa(*(struct in_addr*)&header.ciaddr));
            printf(" - Your IP: %s\n", inet_ntoa(*(struct in_addr*)&header.yiaddr));
            printf(" - Server IP: %s\n", inet_ntoa(*(struct in_addr*)&header.siaddr));
            printf(" - Gateway IP: %s\n", inet_ntoa(*(struct in_addr*)&header.giaddr));
            printf(" - Client MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   header.chaddr[0], header.chaddr[1], header.chaddr[2],
                   header.chaddr[3], header.chaddr[4], header.chaddr[5]);
            printf(" - Server Name: %s\n", header.sname);
            printf(" - Boot Filename: %s\n", header.file);

            // Удаление пакета из массива
            receivedDhcpPackets.erase(it);
            packetFound = true;
            break;
        }
    }

    if (!packetFound) {
        printf("No matching packet found.\n");
    }
}

int main() {
    // Здесь передайте необходимые параметры для отправки DHCP пакета
    const char* interface = "eth0";
    const char* source_mac = "00:11:22:33:44:55";
    const char* source_ip = "192.168.1.2";
    const char* target_mac = "ff:ff:ff:ff:ff:ff"; // Broadcast MAC для DHCP
    const char* target_ip = "255.255.255.255"; // Broadcast IP для DHCP

    // Заполните остальные поля DHCP пакета
    u_int32_t transaction_id = 123456;
    u_short secs = 10;
    u_short flags = 0;
    u_int32_t client_ip = 0; // Неизвестный IP адрес клиента
    u_int32_t your_ip = 0; // Неизвестный IP адрес, который будет присвоен клиенту
    u_int32_t server_ip = 0; // Неизвестный IP адрес DHCP сервера
    u_int32_t gateway_ip = 0; // Неизвестный IP адрес шлюза
    const char* client_mac = "00:11:22:33:44:55"; // MAC адрес клиента
    const char* server_name = "myserver"; // Имя DHCP сервера
    const char* filename = "bootfile"; // Имя файла загрузки

    // Отправка DHCP пакета и ожидание ответа
    send_dhcp_packet(interface, source_mac, source_ip, target_mac, target_ip, transaction_id, secs, flags,
                     client_ip, your_ip, server_ip, gateway_ip, client_mac, server_name, filename);

    // Прием и сравнение DHCP пакета
    receive_dhcp_packet(transaction_id, secs, flags, client_ip, your_ip, server_ip, gateway_ip, client_mac, server_name, filename);

    return 0;
}
