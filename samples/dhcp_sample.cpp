int clientSocket;

// Структура для заголовка DHCP пакета
struct DhcpHeader {
    uint8_t op;              // Message op code / message type.
    uint8_t htype;           // Hardware address type.
    uint8_t hlen;            // Hardware address length.
    uint8_t hops;            // Hops.
    uint32_t xid;            // Transaction ID.
    uint16_t secs;           // Seconds elapsed.
    uint16_t flags;          // Bootp flags.
    struct in_addr ciaddr;   // Client IP address.
    struct in_addr yiaddr;   // 'Your' IP address.
    struct in_addr siaddr;   // IP address of next server to use in bootstrap.
    struct in_addr giaddr;   // Relay agent IP address.
    uint8_t chaddr[16];      // Client hardware address.
    uint8_t sname[64];       // Optional server host name.
    uint8_t file[128];       // Boot file name.
    uint32_t magicCookie;    // Magic cookie.
    uint8_t options[312];    // Optional parameters.
};

struct ReceivedPacket {
    DhcpHeader dhcpHeader;
    int sourcePort;
};

std::vector<ReceivedPacket> receivedPackets;

// Функция отправки DHCP пакета
void send_dhcp_packet() {
    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    const char* ipAddress = "255.255.255.255"; // Broadcast address

    if (clientSocket < 0) {
        perror("Error creating socket");
        return;
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(67); // DHCP server port
    serverAddress.sin_addr.s_addr = inet_addr(ipAddress);

    // Создание сокета
    clientSocket = socket(AF_INET, SOCK_DGRAM, 0);

    // Формирование DHCP пакета
    DhcpHeader dhcpPacket;
    // Заполнение dhcpPacket данными

    // Отправка DHCP пакета
    sendto(clientSocket, &dhcpPacket, sizeof(dhcpPacket), 0, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
}

// Функция принятия DHCP пакета
void receive_dhcp_packet() {
    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof(clientAddress);
    char buffer[1024]; // Буфер для приёма данных

    // Создание сокета
    int serverSocket = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons(68); // DHCP client port

    // Привязка сокета к адресу
    bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

    // Получение данных
    recvfrom(serverSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, &addrLen);

    // Обработка полученных данных
    ReceivedPacket receivedPacket;
    receivedPacket.sourcePort = ntohs(clientAddress.sin_port);
    // Заполнение receivedPacket данными из буфера, если необходимо

    receivedPackets.push_back(receivedPacket);
}
