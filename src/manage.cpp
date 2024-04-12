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


uint16_t pcap_in_cksum(unsigned short *addr, int len);
int HEX_TO_DEC(const std::string &st);

std::string var = "int main() {\n}";

void callTcp(bool isScanner, const u_char *receivedPacket, char *appData){
    tcp_header* th = *receivedPacket;
    if(isScanner) {
        std::sprintf(appData, "\tsend_tcp_packet(%02x, %d, %02x, %02x, %2x, %d,%02x, 0x%02x );\n",
                     HEX_TO_DEC(std::to_string(iph.identification)), iph.ttl, HEX_TO_DEC(std::to_string(th.th_win)),
                     HEX_TO_DEC(std::to_string(ntohs(th.sport))),
                     HEX_TO_DEC(std::to_string(ntohs(th.dport))), HEX_TO_DEC(std::to_string(ntohs(th.th_seq))),
                     HEX_TO_DEC(std::to_string(ntohs(th.th_ack))), th.th_flags);
    }
    else {
        std::sprintf(appData, "\tlisten_tcp_packet(%02x, 0x%02x);\n",
                     HEX_TO_DEC(std::to_string(ntohs(th.dport))), th.th_flags);

    }
}

void callUdp(bool isScanner, const u_char *receivedPacket, char *appData){
    tcp_header* uh = *receivedPacket;
    if (isScanner) {
        //TODO По аналогии заполнение полей по аналогии с TCP

    }
    else {
        //TODO По аналогии заполнение полей по аналогии с TCP
    }
}

void callDHCP(bool isScanner, const u_char *receivedPacket, char *appData){
    tcp_header* dhcph = *receivedPacket;
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
        callTcp(true, receivedPacket, *appData);
    }
    else if(proto == 17){
        callUdp(true, receivedPacket, *appData);
    }
    else if(proto == 67){
        callDHCP(true, receivedPacket, *appData);
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
        callTcp(false, receivedPacket, *appData);
    }
    else if(proto == 17){
        callUdp(false, receivedPacket, *appData);
    }
    else if(proto == 67){
        callDHCP(false, receivedPacket, *appData);
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
    ip_header *iph = (ip_header *)(receivedPacket + SIZE_ETHERNET);
    tcp_header* th = *receivedPacket;
    iph.ver_ihl = (4 << 4) | (sizeof(ip_header) / 4); // Версия и длина заголовка
    iph.tlen = htons(sizeof(ip_header) + sizeof(tcp_header));

    u_char *optionsPtr = reinterpret_cast<u_char*>(&th) + SIZE_TCP;

// Вычисляем смещение опций
    int offset = (th.th_offx2 >> 4) - 5;

// Печать для отладки
    std::cout << "Size of TCP header: " << SIZE_TCP << std::endl;
    std::cout << "Offset to options: " << (th.th_offx2 >> 4) * 4 << std::endl;
    std::cout << "Options start address: " << std::hex << (void*)optionsPtr << std::endl;

    // Обрабатываем опции
    processTCPOptions(optionsPtr, offset, th);



    iph.crc = htons(pcap_in_cksum(reinterpret_cast<unsigned short *>(&iph), sizeof(ip_header)));


    th.th_sum = htons(pcap_in_cksum(reinterpret_cast<unsigned short *>(&th), sizeof(tcp_header)));

    std::cout << "IP Header Version: " << std::hex << ((iph.ver_ihl & 0xF0) >> 4) << std::endl;
    std::cout << "IP Header IHL: " << std::hex << (iph.ver_ihl & 0x0F) << std::endl;
    std::cout << "TCP Header Sport: " << ntohs(th.sport) << std::endl;
    std::cout << "TCP Header Dport: " << ntohs(th.dport) << std::endl;
    std::cout << "TCP Header flags: " << th.th_flags << std::endl;
}

// теперь это не менеджер, а анализатор и надо сделать большой рефаторинг кода: декомпозицию компонент чтобы не дублировать код для каждого протокола

void manager(const u_char *receivedPacket, bool is_scanner, int proto)
{
    if (ip_hdr->proto == 6)
    {
        // Копируем содержимое tcp_sample.cpp в tcp_result.cpp
        std::ifstream inputTemplate("sample/tcp_sample.cpp");
        std::ofstream outputResult("result/tcp_result.cpp");

        if (!inputTemplate || !outputResult)
        {
            std::cerr << "Не удалось открыть файлы tcp_sample.cpp или tcp_result.cpp\n";
            return;
        }
        outputResult << inputTemplate.rdbuf();
        inputTemplate.close();
        outputResult.close();
        fillTCPPacket(*receivedPacket);
        if (is_scanner) {
            fillFieldsScanner(*receivedPacket, 6, "results/tcp_result.cpp");
        }
        else {
            fillFieldsVictim(*receivedPacket, 6, "results/tcp_result.cpp");
        }
    }
    else if(proto == 17){

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

int HEX_TO_DEC(const std::string &st)
{
    int i, s, k, p;
    s = 0;
    p = st.length() - 1;
    for (i = 0; st[i] != '\0'; i++)
    {
        switch (toupper(st[i]))
        {
            case 'a':
                k = 10;
                break;
            case 'b':
                k = 11;
                break;
            case 'c':
                k = 12;
                break;
            case 'd':
                k = 13;
                break;
            case 'e':
                k = 14;
                break;
            case 'f':
                k = 15;
                break;
            case '1':
                k = 1;
                break;
            case '2':
                k = 2;
                break;
            case '3':
                k = 3;
                break;
            case '4':
                k = 4;
                break;
            case '5':
                k = 5;
                break;
            case '6':
                k = 6;
                break;
            case '7':
                k = 7;
                break;
            case '8':
                k = 8;
                break;
            case '9':
                k = 9;
                break;
            case '0':
                k = 0;
                break;
        }
        s = s + k * pow(16, p);
        p--;
    }
    std::cout << s << std::endl;
    return s;
}