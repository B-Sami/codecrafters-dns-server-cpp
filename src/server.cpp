#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

void create_dns_header(char* response) {
    uint16_t packetID = htons(1234);       // 2 bytes, Packet Identifier
    uint16_t flags = htons(0x8180);        // 2 bytes, QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
    uint16_t qdcount = htons(1);           // 2 bytes, Question Count
    uint16_t ancount = htons(1);           // 2 bytes, Answer Record Count (updated to 1)
    uint16_t nscount = htons(0);           // 2 bytes, Authority Record Count
    uint16_t arcount = htons(0);           // 2 bytes, Additional Record Count

    memcpy(response, &packetID, 2);
    memcpy(response + 2, &flags, 2);
    memcpy(response + 4, &qdcount, 2);
    memcpy(response + 6, &ancount, 2);
    memcpy(response + 8, &nscount, 2);
    memcpy(response + 10, &arcount, 2);
}

size_t create_question(char* response) {
    unsigned char domain[] = {
        12, 'c','o','d','e','c','r','a','f','t','e','r','s',
        2, 'i','o',
        0  // Null terminator
    };
    
    size_t domainLength = sizeof(domain);
    memcpy(response, domain, domainLength);

    uint16_t qtype = htons(1);  // A record
    memcpy(response + domainLength, &qtype, 2);

    uint16_t qclass = htons(1);  // IN class
    memcpy(response + domainLength + 2, &qclass, 2);

    return domainLength + 4; // Domain length + Type (2 bytes) + Class (2 bytes)
}

size_t create_answer(char* response) {
    unsigned char domain[] = {
        12, 'c','o','d','e','c','r','a','f','t','e','r','s',
        2, 'i','o',
        0  // Null terminator
    };
    
    size_t domainLength = sizeof(domain);
    memcpy(response, domain, domainLength);

    uint16_t type = htons(1);  // A record
    memcpy(response + domainLength, &type, 2);

    uint16_t class_ = htons(1);  // IN class
    memcpy(response + domainLength + 2, &class_, 2);

    uint32_t ttl = htonl(60);  // TTL of 60 seconds
    memcpy(response + domainLength + 4, &ttl, 4);

    uint16_t rdlength = htons(4);  // Length of RDATA (4 bytes for IPv4)
    memcpy(response + domainLength + 8, &rdlength, 2);

    uint32_t ip = htonl(0x08080808);  // 8.8.8.8 as an example IP
    memcpy(response + domainLength + 10, &ip, 4);

    return domainLength + 14;  // Domain length + 10 bytes for other fields + 4 bytes for IP
}

int main() {
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == -1) {
        std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
        return 1;
    }

    int reuse = 1;
    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
        return 1;
    }

    sockaddr_in serv_addr = {};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(2053);
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(udpSocket, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) != 0) {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        return 1;
    }

    char buffer[512];
    char response[512];
    struct sockaddr_in clientAddress;
    socklen_t clientAddrLen = sizeof(clientAddress);

    while (true) {
        int bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, 
                                 reinterpret_cast<struct sockaddr*>(&clientAddress), 
                                 &clientAddrLen);
        if (bytesRead == -1) {
            perror("Error receiving data");
            continue;
        }

        // Create DNS response
        create_dns_header(response);
        size_t questionSize = create_question(response + 12);
        size_t answerSize = create_answer(response + 12 + questionSize);
        size_t responseSize = 12 + questionSize + answerSize;

        if (sendto(udpSocket, response, responseSize, 0, 
                   reinterpret_cast<struct sockaddr*>(&clientAddress), 
                   sizeof(clientAddress)) == -1) {
            perror("Failed to send response");
        }
    }

    close(udpSocket);
    return 0;
}

