struct IcmpHeader {
    uint8_t type;           // Тип сообщения ICMP
    uint8_t code;           // Код сообщения ICMP
    uint16_t checksum;      // Контрольная сумма
    uint16_t identifier;    // Идентификатор
    uint16_t sequenceNumber;// Порядковый номер
    // Данные ICMP пакета (можно добавить по желанию)
};

struct ReceivedPacket {
    IcmpHeader icmpHeader;
    int sourcePort;
};

std::vector<ReceivedPacket> receivedPackets;

void send_and_receive_icmp_packet(const char* dest_ip) {
    int clientSocket;

    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));

    clientSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (clientSocket < 0) {
        perror("Error creating socket");
        return;
    }

    serverAddress.sin_family = AF_INET;
    inet_pton(AF_INET, dest_ip, &serverAddress.sin_addr);

    IcmpHeader icmpPacket;
    memset(&icmpPacket, 0, sizeof(icmpPacket));
    icmpPacket.type = 8; // ICMP Echo Request
    icmpPacket.code = 0;
    icmpPacket.identifier = getpid();
    icmpPacket.sequenceNumber = 1;
    icmpPacket.checksum = 0; // Вычислится автоматически при отправке

    // Отправляем ICMP пакет
    sendto(clientSocket, &icmpPacket, sizeof(icmpPacket), 0, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

    // Ожидаем прихода ICMP пакета
    struct sockaddr_in senderAddress;
    socklen_t senderAddrLen = sizeof(senderAddress);
    char buffer[1024]; // Буфер для приёма данных
    ssize_t dataSize = recvfrom(clientSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&senderAddress, &senderAddrLen);

    // Создаем объект ReceivedPacket и записываем его в вектор
    ReceivedPacket receivedPacket;
    memcpy(&receivedPacket.icmpHeader, buffer, sizeof(IcmpHeader));
    receivedPacket.sourcePort = ntohs(senderAddress.sin_port);
    receivedPackets.push_back(receivedPacket);

    close(clientSocket);
}

void process_received_packet() {
    if (receivedPackets.empty()) {
        std::cout << "No ICMP packets to process.\n";
        return;
    }

    // Получаем первый пакет из вектора
    ReceivedPacket packet = receivedPackets.front();

    // Выводим информацию о пакете
    std::cout << "Received ICMP packet:\n"
              << "Type: " << static_cast<int>(packet.icmpHeader.type) << "\n"
              << "Code: " << static_cast<int>(packet.icmpHeader.code) << "\n"
              << "Checksum: " << ntohs(packet.icmpHeader.checksum) << "\n"
              << "Identifier: " << ntohs(packet.icmpHeader.identifier) << "\n"
              << "Sequence Number: " << ntohs(packet.icmpHeader.sequenceNumber) << "\n"
              << "Source Port: " << packet.sourcePort << "\n";

    // Удаляем обработанный пакет из вектора
    receivedPackets.erase(receivedPackets.begin());
}

int main() {
    const char* dest_ip = "127.0.0.1"; // IP-адрес, на который отправляется ICMP пакет

    // Отправляем и принимаем ICMP пакет
    send_and_receive_icmp_packet(dest_ip);

    // Обрабатываем полученный ICMP пакет
    process_received_packet();

    return 0;
}
