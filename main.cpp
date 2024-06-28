#include <iostream>
#include "src/traffic_parser.h"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Использование: ./main var1 var2" << std::endl;
        return 1;
    }

    std::string ip_scanner = argv[1];
    std::string ip_victim = argv[2];

    std::cout << "IP scanner: " << ip_scanner << std::endl;
    std::cout << "IP victim: " << ip_victim << std::endl;

    traffic_parser("traffic/icmp-flood-traffic.pcapng",ip_scanner,ip_victim);
    return 1;
}