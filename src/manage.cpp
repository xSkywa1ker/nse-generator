#include <iostream>
#include <fstream>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <iomanip>
#include <cmath>

#define MAX_PACKET_LIFETIME 120 // Максимальное время жизни пакета в секундах
#define MAX_PACKET_SIZE 65535   // Максимальная длина пакета
#define SIZE_ETHERNET 14
#define SIZE_TCP (sizeof(tcp_header) - sizeof(u_short) - sizeof(bool))
#define SIZE_IP 20
#define SIZE_ICMP 8
#define SIZE_UDP 8
#define MAX_OPTION_SIZE 40

typedef struct arp_header {
    u_short hardware_type;     // Тип аппаратного устройства
    u_short protocol_type;     // Тип протокола
    u_char hardware_len;       // Длина аппаратного адреса
    u_char protocol_len;       // Длина протокольного адреса
    u_short opcode;            // Операционный код
    u_char sender_mac[6];     // MAC-адрес отправителя
    u_char sender_ip[4];      // IP-адрес отправителя
    u_char target_mac[6];     // MAC-адрес получателя
    u_char target_ip[4];      // IP-адрес получателя
} arp_header;

typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

typedef struct ethernet_header
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;
} ethernet_header;

typedef struct ip_header
{
    u_char ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char tos;            // Type of service
    u_short tlen;          // Total length
    u_short identification; // Identification
    u_short flags_fo;      // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl;            // Time to live
    u_char proto;          // Protocol
    u_short crc;           // Header checksum
    ip_address saddr;      // Source address
    ip_address daddr;      // Destination address
} ip_header;

typedef u_int32_t tcp_seq;

typedef struct tcp_header
{
    u_short sport; // Source port
    u_short dport; // Destination port
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
    u_char th_flags;
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
    u_short mss;    // MSS option value
    u_char window_scale; // Window Scale option value
    bool sack_permitted; // SACK Permitted option
} tcp_header;

typedef struct udp_header
{
    u_short sport;
    u_short dport;
    u_short len;
    u_short checksum;
    u_char data[1];
} udp_header;

typedef struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequenceNumber;
} icmp_header;

struct TemplateFlag {
    bool firstCopied = true;
    bool tcpCopied = false;
    bool udpCopied = false;
    bool icmpCopied = false;
    bool dhcpCopied = false;
    bool arpCopied = false;
};

TemplateFlag templateFlag;

uint16_t pcap_in_cksum(unsigned short *addr, int len);
int HEX_TO_DEC(const std::string &st);

std::string var = "int main() {\n}";

void callTcp(bool isScanner, const u_char *receivedPacket, char *appData){
    tcp_header* th = (tcp_header *)receivedPacket;
    if(isScanner) {
        std::sprintf(appData, "\tsend_tcp_packet(%02x, %02x, %2x, %d,%02x, 0x%02x );\n",
                     HEX_TO_DEC(std::to_string(th->th_win)),
                     HEX_TO_DEC(std::to_string(ntohs(th->sport))),
                     HEX_TO_DEC(std::to_string(ntohs(th->dport))), HEX_TO_DEC(std::to_string(ntohs(th->th_seq))),
                     HEX_TO_DEC(std::to_string(ntohs(th->th_ack))), th->th_flags);
    }
    else {
        std::sprintf(appData, "\tlisten_tcp_packet(%02x, 0x%02x);\n",
                     HEX_TO_DEC(std::to_string(ntohs(th->dport))), th->th_flags);

    }
}

void callUdp(bool isScanner, const u_char *receivedPacket, char *appData){
    udp_header* uh = (udp_header *)receivedPacket;
    if(isScanner) {
        std::sprintf(appData, "\tsend_udp_packet(%02x, %02x, %02x, %s);\n",
                     HEX_TO_DEC(std::to_string(ntohs(uh->sport))),
                     HEX_TO_DEC(std::to_string(ntohs(uh->dport))),
                     ntohs(uh->len), uh->data);
    }
    else {
        std::sprintf(appData, "\tlisten_udp_packet(%02x);\n",
                     HEX_TO_DEC(std::to_string(ntohs(uh->dport))));
    }
}

void callICMP(bool isScanner, const u_char *receivedPacket, char *appData){
    icmp_header* ih = (icmp_header *)receivedPacket;
    if(isScanner) {
        std::sprintf(appData, "\tsend_icmp_packet(%02x, %02x, %02x, %02x);\n",
                     HEX_TO_DEC(std::to_string(ih->type)),
                     HEX_TO_DEC(std::to_string(ih->code)),
                     ih->identifier,
                HEX_TO_DEC(std::to_string(ntohs(ih->sequenceNumber))));
    }
    else {
        std::sprintf(appData, "\tlisten_icmp_packet(%02x);\n",
                     HEX_TO_DEC(std::to_string(ih->type)));
    }
}

void callDHCP(bool isScanner, const u_char *receivedPacket, char *appData){
    //tcp_header* dhcph = (dhcp*)receivedPacket;
    if(isScanner) {
        //TODO По аналогии заполнение полей по аналогии с TCP


    }
    else {
        //TODO По аналогии заполнение полей по аналогии с TCP
    }
}

void fillFieldsScanner(const u_char *receivedPacket, int proto, const std::string &outputFile)
{
    std::ofstream output(outputFile, std::ios_base::app);
    if (!output)
    {
        std::cerr << "Не удалось открыть файл для записи\n";
        return;
    }
    ip_header *iph = (ip_header *)(receivedPacket + SIZE_ETHERNET);
    char appData[350];
    if (proto == 6){
        callTcp(true, receivedPacket, appData);
    }
    else if(proto == 17){
        callUdp(true, receivedPacket, appData);
    }
    else if(proto == 67){
        callDHCP(true, receivedPacket, appData);
    }

    // Ищем позицию закрывающей фигурной скобки
    size_t pos = var.rfind("}");

    if (pos != std::string::npos)
    {
        // Вставляем данные перед закрывающей фигурной скобкой
        var.insert(pos, appData);
    }

    output << var;
    output.close();

    std::cout << "Программа успешно выполнена\n";
}

void fillFieldsVictim(const u_char *receivedPacket, int proto, const std::string &outputFile)
{
    std::ofstream output(outputFile, std::ios_base::app);
    if (!output)
    {
        std::cerr << "Не удалось открыть файл для записи\n";
        return;
    }
    ip_header *iph = (ip_header *)(receivedPacket + SIZE_ETHERNET);
    char appData[350];
    if (proto == 6){
        callTcp(false, receivedPacket, appData);
    }
    else if(proto == 17){
        callUdp(false, receivedPacket, appData);
    }
    else if(proto == 67){
        callDHCP(false, receivedPacket, appData);
    }

    // Ищем позицию закрывающей фигурной скобки
    size_t pos = var.rfind("}");

    if (pos != std::string::npos)
    {
        // Вставляем данные перед закрывающей фигурной скобкой
        var.insert(pos, appData);
    }

    output << var;
    output.close();

    std::cout << "Программа успешно выполнена\n";
}

void fillTCPPacket(const u_char *receivedPacket)
{
    ip_header* iph = (ip_header *)(receivedPacket + SIZE_ETHERNET);
    tcp_header* th = (tcp_header *)receivedPacket;
    iph->ver_ihl = (4 << 4) | (sizeof(ip_header) / 4);
    iph->tlen = htons(sizeof(ip_header) + sizeof(tcp_header));
    u_char *optionsPtr = reinterpret_cast<u_char*>(&th) + SIZE_TCP;
    int offset = (th->th_offx2 >> 4) - 5;
    iph->crc = htons(pcap_in_cksum(reinterpret_cast<unsigned short *>(&iph), sizeof(ip_header)));
    th->th_sum = htons(pcap_in_cksum(reinterpret_cast<unsigned short *>(&th), sizeof(tcp_header)));
}

// теперь это не менеджер, а анализатор и надо сделать большой рефаторинг кода: декомпозицию компонент чтобы не дублировать код для каждого протокола

void analizer(const u_char *receivedPacket, bool is_scanner, int proto)
{
    if (templateFlag.firstCopied){
        std::ifstream inputTemplate("samples/includes.cpp");
        std::ofstream outputResult("results/result.cpp");
        if (!inputTemplate || !outputResult)
        {
            std::cerr << "Не удалось открыть файл result.cpp\n";
            return;
        }
        outputResult << inputTemplate.rdbuf();
        templateFlag.firstCopied = false;
        inputTemplate.close();
        outputResult.close();
    }
    ip_header* ip_hdr = (ip_header *)(receivedPacket + SIZE_ETHERNET);
    if (ip_hdr->proto == 6)
    {
        tcp_header *tcpHeader = (tcp_header *)(receivedPacket + 14 + ((ip_hdr->ver_ihl & 0x0F) << 2));
        std::ifstream inputTemplate("samples/tcp_sample.cpp");
        std::ofstream outputResult("results/result.cpp");

        if (!inputTemplate || !outputResult)
        {
            std::cerr << "Не удалось открыть файлы tcp_sample.cpp или result.cpp\n";
            return;
        }
        if (!templateFlag.tcpCopied) {
            // Читаем содержимое шаблона в строку
            std::ifstream inputTemplate("samples/tcp_sample.cpp");
            if (inputTemplate) {
                std::ostringstream buffer;
                buffer << inputTemplate.rdbuf();
                templateContent = buffer.str();
                inputTemplate.close();
            } else {
                std::cerr << "Не удалось открыть файл tcp_sample.cpp\n";
                return;
            }

            // Ищем позицию последнего вхождения инструкции #include
            size_t lastIncludePos = outputResult.str().rfind("#include");
            if (lastIncludePos != std::string::npos) {
                // Вставляем содержимое шаблона после последнего #include
                outputResult.seekp(lastIncludePos + 8); // Смещаемся на конец #include
                outputResult << "\n" << templateContent;
            } else {
                // Если инструкция #include не найдена, просто вставляем в конец файла
                outputResult.seekp(0, std::ios_base::end);
                outputResult << "\n" << templateContent;
            }
            templateFlag.tcpCopied = true;
        }
        inputTemplate.close();
        outputResult.close();
        fillTCPPacket(receivedPacket);
        if (is_scanner) {
            fillFieldsScanner(receivedPacket, 6, "results/result.cpp");
        }
        else {
            fillFieldsVictim(receivedPacket, 6, "results/result.cpp");
        }
    }
    else if(proto == 17){
        udp_header *udpHeader = (udp_header *)(receivedPacket + 14 + ((ip_hdr->ver_ihl & 0x0F) * 4));
        std::ifstream inputTemplate("samples/udp_sample.cpp");
        std::ofstream outputResult("results/udp_result.cpp");

        if (!inputTemplate || !outputResult)
        {
            std::cerr << "Не удалось открыть файлы udp_sample.cpp или udp_sample.cpp\n";
            return;
        }
        if (!templateFlag.udpCopied) {
            outputResult << inputTemplate.rdbuf();
            templateFlag.udpCopied = true;
        }
        inputTemplate.close();
        outputResult.close();
        if (is_scanner) {
            fillFieldsScanner(receivedPacket, 17, "results/udp_result.cpp");
        }
        else {
            fillFieldsVictim(receivedPacket, 17, "results/udp_result.cpp");
        }
    }
    else if (proto == 2){
        icmp_header *icmpHeader = (icmp_header *)(receivedPacket + 14 + ((ip_hdr->ver_ihl & 0x0F) * 4));
        std::ifstream inputTemplate("samples/icmp_sample.cpp");
        std::ofstream outputResult("result/icmp_result.cpp");

        if (!inputTemplate || !outputResult)
        {
            std::cerr << "Не удалось открыть файлы udp_sample.cpp или udp_sample.cpp\n";
            return;
        }
        if (!templateFlag.icmpCopied) {
            outputResult << inputTemplate.rdbuf();
            templateFlag.icmpCopied = true;
        }
        inputTemplate.close();
        outputResult.close();
        if (is_scanner) {
            fillFieldsScanner(receivedPacket, 2, "results/icmp_result.cpp");
        }
        else {
            fillFieldsVictim(receivedPacket, 2, "results/icmp_result.cpp");
        }
    }
}

// Функция для вычисления контрольной суммы
uint16_t pcap_in_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

int HEX_TO_DEC(const std::string &st) {
    int num = 0;
    for (char i : st) {
        if (i >= '0' && i <= '9') {
            num = num * 16 + (i - '0');
        } else if (i >= 'a' && i <= 'f') {
            num = num * 16 + (i - 'a' + 10);
        } else if (i >= 'A' && i <= 'F') {
            num = num * 16 + (i - 'A' + 10);
        }
    }
    return num;
}
