#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>

struct PingConfig {
    std::string target_ip;
    int timeout_sec = 2;
    uint16_t packet_id = static_cast<uint16_t>(getpid());
};

// RAII обертка над сокетами
class Socket {
public:
    Socket(int domain, int type, int protocol) {
        fd_ = socket(domain, type, protocol);
        if (fd_ < 0) {
            throw std::runtime_error("Failed to create socket");
        }
        
    }
    ~Socket() {
        if (fd_ >= 0) {
            close(fd_);
        }
    }
    int get() const {return fd_;}
private:
    int fd_ = -1;
};

// подсчет контрольной суммы
uint16_t calculate_checksum(const void* data, size_t length) {
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);
    uint32_t sum = 0;


    for (;length > 1; length -= 2) {
        sum += *ptr++;

    }
    if (length== 1) {
        sum += *reinterpret_cast<const uint8_t*>(ptr);

    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
    
}

// создание icmp пакета
struct icmphdr create_icmp_echo_request(uint16_t id, uint16_t sequence) {
    struct icmphdr packet {};
    packet.type = ICMP_ECHO;
    packet.code = 0;
    packet.un.echo.id = id;
    packet.un.echo.sequence = sequence;
    packet.checksum = calculate_checksum(&packet, sizeof(packet));
    return packet;
}

// отправка и получение mac
std::string ping_and_get_mac(const PingConfig& config) {
    // raw сокет для отправки ping
    Socket icmp_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    // raw сокет для получения ethernet фрейма
    Socket raw_socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    struct timeval tv {
        .tv_sec = config.timeout_sec,
        .tv_usec = 0
    };


    if (setsockopt(raw_socket.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        throw std::runtime_error("Failed to set socket timeout");
    }
    
    // структура для Ipv4 адреса
    struct sockaddr_in dest_addr {};
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, config.target_ip.c_str(), &dest_addr.sin_addr) != 1) {
        throw::std::runtime_error("Invalid IP address");
    }
    
    // отправка icmp запроса
    auto icmp_packet = create_icmp_echo_request(config.packet_id, 1);
    if (sendto(icmp_socket.get(), &icmp_packet, sizeof(icmp_packet), 0,
    reinterpret_cast<struct sockaddr*>(&dest_addr), sizeof(dest_addr)) < 0) {
        throw std::runtime_error("Failed to send ICMP request");
    }

    // получение ethernet-фрейма с mac адресом
    char buffer[1024];
    struct sockaddr_ll src_addr {};
    socklen_t addr_len = sizeof(src_addr);
    ssize_t recv_len = recvfrom(raw_socket.get(), buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr*>(&src_addr), &addr_len);

    if (recv_len <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            throw std::runtime_error("Timeout: no reply received");
        } else {
            throw std::runtime_error("recvfrom failed: " + std::string(strerror(errno)));
        }
    }

    // извлекаем mac адрес
    auto* eth_header = reinterpret_cast<struct ethhdr*>(buffer);
    if (eth_header->h_proto != htons(ETH_P_IP)) {
        throw std::runtime_error("Not an IP packet");
    }

    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
    eth_header->h_source[0], eth_header->h_source[1], eth_header->h_source[2],
    eth_header->h_source[3], eth_header->h_source[4], eth_header->h_source[5]);

    return std::string(mac_str);

}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <IPv4 address>" << std::endl;
        return 1;
    }
    try {
        PingConfig config;
        config.target_ip = argv[1];

        auto mac = ping_and_get_mac(config);
        std::cout << "Source MAC: " << mac << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;

}
