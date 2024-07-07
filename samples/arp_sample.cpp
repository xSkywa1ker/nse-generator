
struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
};

std::vector<std::vector<unsigned char>> received_packets;

void process_received_arp_packets(unsigned short filter_opcode) {
    for (const auto& packet : received_packets) {
        struct ethhdr* eth = (struct ethhdr*)packet.data();
        if (ntohs(eth->h_proto) == ETH_P_ARP) {
            struct arp_header* arp = (struct arp_header*)(packet.data() + sizeof(struct ethhdr));
            if (ntohs(arp->opcode) == filter_opcode) {
                char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, arp->sender_ip, sender_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, arp->target_ip, target_ip, INET_ADDRSTRLEN);

                std::cout << "Received ARP packet with matching opcode:\n";
                std::cout << "Sender MAC: ";
                for (int i = 0; i < 6; i++) std::cout << std::hex << +arp->sender_mac[i] << (i < 5 ? ":" : "\n");
                std::cout << "Sender IP: " << sender_ip << "\n";
                std::cout << "Target MAC: ";
                for (int i = 0; i < 6; i++) std::cout << std::hex << +arp->target_mac[i] << (i < 5 ? ":" : "\n");
                std::cout << "Target IP: " << target_ip << "\n";
                std::cout << "Opcode: " << ntohs(arp->opcode) << " (1=request, 2=reply)\n";
            }
        }
    }
}

bool parse_mac_address(const std::string& mac_str, unsigned char* mac) {
    std::istringstream iss(mac_str);
    int value;
    char colon;

    for (int i = 0; i < 5; ++i) {
        if (!(iss >> std::hex >> value >> colon) || colon != ':') {
            return false;
        }
        mac[i] = static_cast<unsigned char>(value);
    }
    if (!(iss >> std::hex >> value)) {
        return false;
    }
    mac[5] = static_cast<unsigned char>(value);
    return true;
}

void print_mac_address(const char* prefix, const unsigned char* mac) {
    std::cout << prefix << std::hex;
    for (int i = 0; i < 6; ++i) {
        std::cout << (i ? ":" : "") << +mac[i];
    }
    std::cout << std::dec << std::endl;
}

void send_and_receive_arp_packet(const char* interface, const char* source_mac_address_str, const char* source_ip,
                                 const char* target_mac_address_str, const char* target_ip) {
    unsigned char source_mac[6], target_mac[6];
    if (!parse_mac_address(source_mac_address_str, source_mac) || !parse_mac_address(target_mac_address_str, target_mac)) {
        std::cerr << "Error parsing MAC addresses." << std::endl;
        return;
    }

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd == -1) {
        perror("socket");
        return;
    }

    struct timeval tv = {1, 0};  // 1 second timeout
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    struct sockaddr_ll socket_address = {};
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = if_nametoindex(interface);
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, target_mac, ETH_ALEN);

    unsigned char packet[60] = {};
    struct ethhdr* eth = (struct ethhdr*)packet;
    memcpy(eth->h_dest, target_mac, ETH_ALEN);
    memcpy(eth->h_source, source_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_ARP);

    struct arp_header* arp = (struct arp_header*)(packet + sizeof(struct ethhdr));
    arp->hardware_type = htons(ARPHRD_ETHER);
    arp->protocol_type = htons(ETH_P_IP);
    arp->hardware_len = 6;
    arp->protocol_len = 4;
    arp->opcode = htons(ARPOP_REQUEST);
    memcpy(arp->sender_mac, source_mac, 6);
    inet_pton(AF_INET, source_ip, arp->sender_ip);
    memcpy(arp->target_mac, target_mac, 6);
    inet_pton(AF_INET, target_ip, arp->target_ip);

    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) == -1) {
        perror("sendto");
    } else {
        std::cout << "ARP request sent.\n";
    }

    char buffer[2048];
    int length = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
    if (length == -1) {
        if (errno == EWOULDBLOCK) {
            std::cout << "Receive timed out\n";
        } else {
            perror("recvfrom");
        }
    } else if (length > 0) {
        std::cout << "ARP response received.\n";
        // Process the received packet if needed
    }

    close(sockfd);
}
