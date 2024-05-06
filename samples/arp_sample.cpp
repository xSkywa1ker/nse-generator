#include <iostream>
#include <vector>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if_arp.h>

#define MAX_PACKETS 100

struct ArpHeader {
    u_short hardwareType;
    u_short protocolType;
    u_char hardwareSize;
    u_char protocolSize;
    u_short opcode;
    u_char senderMAC[6];
    u_char senderIP[4];
    u_char targetMAC[6];
    u_char targetIP[4];
};

struct ReceivedArpPacket {
    ArpHeader arpHeader;
};

std::vector<ReceivedArpPacket> receivedArpPackets;

void send_and_receive_arp_packet(const char* source_ip, const char* dest_ip) {
    // Создание сокета
    int clientSocket = socket(AF_PACKET, SOCK_PACKET, htons(ETH_P_ARP));
    if (clientSocket < 0) {
        perror("Error creating socket");
        return;
    }

    // Заполнение структуры с информацией об ARP запросе
    ArpHeader arpHeader;
    arpHeader.hardwareType = htons(ARPHRD_ETHER);
    arpHeader.protocolType = htons(ETH_P_IP);
    arpHeader.hardwareSize = 6;
    arpHeader.protocolSize = 4;
    arpHeader.opcode = htons(ARPOP_REQUEST);

    // Заполнение MAC и IP адресов отправителя
    // В реальном приложении эти данные должны быть заполнены с использованием реальных MAC и IP адресов вашего устройства
    memset(arpHeader.senderMAC, 0xff, 6); // Broadcast MAC
    inet_pton(AF_INET, source_ip, arpHeader.senderIP);

    // Заполнение MAC адреса получателя
    memset(arpHeader.targetMAC, 0, 6); // Unknown MAC
    inet_pton(AF_INET, dest_ip, arpHeader.targetIP);

    // Отправка ARP запроса
    struct sockaddr addr;
    memset(&addr, 0, sizeof(addr));
    strcpy(addr.sa_data, "eth0"); // Укажите имя сетевого интерфейса, с которого отправляется пакет

    sendto(clientSocket, &arpHeader, sizeof(ArpHeader), 0, &addr, sizeof(addr));

    // Получение ARP ответов
    char receivedBuffer[1024];
    while (true) {
        int bytesReceived = recvfrom(clientSocket, receivedBuffer, sizeof(receivedBuffer), 0, NULL, NULL);
        if (bytesReceived > 0) {
            // Обработка полученных данных
            ReceivedArpPacket receivedArpPacket;
            memcpy(&receivedArpPacket.arpHeader, receivedBuffer, sizeof(ArpHeader));
            receivedArpPackets.push_back(receivedArpPacket);

            // Вывод полей ARP пакета
            std::cout << "ARP Response Received:" << std::endl;
            std::cout << "Sender MAC: ";
            for (int i = 0; i < 6; ++i) {
                printf("%02X ", receivedArpPacket.arpHeader.senderMAC[i]);
            }
            std::cout << std::endl;

            std::cout << "Sender IP: ";
            for (int i = 0; i < 4; ++i) {
                std::cout << (int)receivedArpPacket.arpHeader.senderIP[i] << ".";
            }
            std::cout << std::endl;

            // Другие поля ARP пакета могут быть обработаны аналогичным образом
        }
    }

    // Закрытие сокета
    close(clientSocket);
}

int main() {
    const char* source_ip = "192.168.1.2"; // Замените на IP адрес вашего устройства
    const char* dest_ip = "192.168.1.1"; // Замените на IP адрес устройства, которое вы хотите запросить

    // Отправка ARP запроса и получение ответов
    send_and_receive_arp_packet(source_ip, dest_ip);

    return 0;
}
