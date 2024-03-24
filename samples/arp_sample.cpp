#include <iostream>
#include <cstring>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>

// Структура для заголовка ARP пакета
struct ArpHeader {
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t hardwareSize;
    uint8_t protocolSize;
    uint16_t opcode;
    uint8_t senderMac[6];
    uint32_t senderIp;
    uint8_t targetMac[6];
    uint32_t targetIp;
};

struct ReceivedPacket {
    ArpHeader arpHeader;
    int sourcePort;
};

std::vector<ReceivedPacket> receivedPackets;

// Функция отправки ARP пакета
void send_arp_packet(const char* src_mac, uint32_t src_ip, const char* dst_mac, uint32_t dst_ip) {
    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));

    if (clientSocket < 0) {
        perror("Error creating socket");
        return;
    }

    serverAddress.sin_family = AF_PACKET;
    // Укажите соответствующий сетевой интерфейс
    serverAddress.sin_port = htons(0); // Произвольный порт

    // Создание сокета
    clientSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    // Формирование ARP пакета
    ArpHeader arpPacket;
    arpPacket.hardwareType = htons(ARPHRD_ETHER); // Ethernet
    arpPacket.protocolType = htons(ETH_P_IP);     // IPv4
    arpPacket.hardwareSize = 6;                  // Размер MAC-адреса
    arpPacket.protocolSize = 4;                  // Размер IPv4-адреса
    arpPacket.opcode = htons(ARPOP_REQUEST);      // ARP запрос

}

// Функция принятия ARP пакета
void receive_arp_packet() {
    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof(clientAddress);
    char buffer[1024]; // Буфер для приёма данных

    // Создание сокета
    int serverSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    // Получение данных
    recvfrom(serverSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, &addrLen);

    // Обработка полученных данных
    ReceivedPacket receivedPacket;
    // Заполнение receivedPacket данными из буфера, если необходимо

    receivedPackets.push_back(receivedPacket);
}
