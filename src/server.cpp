#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>


void create_dns_header(char* response) {
    uint16_t packetID = htons(1234);       // 2 bytes, Packet Identifier
    uint16_t flags = htons(0x8000);        // 2 bytes, QR=1, OPCODE=0, AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
    uint16_t qdcount = htons(0);           // 2 bytes, Question Count
    uint16_t ancount = htons(0);           // 2 bytes, Answer Record Count
    uint16_t nscount = htons(0);           // 2 bytes, Authority Record Count
    uint16_t arcount = htons(0);           // 2 bytes, Additional Record Count

    memcpy(response, &packetID, 2);
    memcpy(response + 2, &flags, 2);
    memcpy(response + 4, &qdcount, 2);
    memcpy(response + 6, &ancount, 2);
    memcpy(response + 8, &nscount, 2);
    memcpy(response + 10, &arcount, 2);
}

int main() {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    // Create a UDP socket
    int udpSocket;
    struct sockaddr_in clientAddress;

    udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == -1) {
        std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
        return 1;
    }

    // Set socket options to reuse port
    int reuse = 1;
    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
        return 1;
    }

    // Bind the socket to port 2053
    sockaddr_in serv_addr = {};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(2053);
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(udpSocket, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) != 0) {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        return 1;
    }

    // Buffer to store received data
    char buffer[512];
    socklen_t clientAddrLen = sizeof(clientAddress);

    while (true) {
        // Receive data from the client
        int bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr*>(&clientAddress), &clientAddrLen);
        if (bytesRead == -1) {
            perror("Error receiving data");
            break;
        }

        std::cout << "Received " << bytesRead << " bytes from " << inet_ntoa(clientAddress.sin_addr) << std::endl;

        // Prepare the DNS response header
        char response[12];
        create_dns_header(response);

        // Send the response back to the client
        if (sendto(udpSocket, response, sizeof(response), 0, reinterpret_cast<struct sockaddr*>(&clientAddress), sizeof(clientAddress)) == -1) {
            perror("Failed to send response");
        } else {
            std::cout << "Sent DNS header response to " << inet_ntoa(clientAddress.sin_addr) << std::endl;
        }
    }

    close(udpSocket);
    return 0;
}