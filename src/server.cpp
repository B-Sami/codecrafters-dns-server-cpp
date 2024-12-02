#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>
#include <algorithm>

struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct DNSQuestion {
    std::vector<uint8_t> qname;
    uint16_t qtype;
    uint16_t qclass;
};

void create_dns_header(char* response, const DNSHeader& request_header) {
    DNSHeader response_header;
    response_header.id = request_header.id;
    
    uint16_t qr = 1;
    uint16_t opcode = (ntohs(request_header.flags) >> 11) & 0xF;
    uint16_t aa = 0;
    uint16_t tc = 0;
    uint16_t rd = (ntohs(request_header.flags) >> 8) & 0x1;
    uint16_t ra = 0;
    uint16_t z = 0;
    uint16_t rcode = (opcode == 0) ? 0 : 4;

    response_header.flags = htons((qr << 15) | (opcode << 11) | (aa << 10) | (tc << 9) | (rd << 8) | (ra << 7) | (z << 4) | rcode);
    
    response_header.qdcount = htons(1);
    response_header.ancount = htons(1);
    response_header.nscount = htons(0);
    response_header.arcount = htons(0);

    memcpy(response, &response_header, sizeof(DNSHeader));
}

DNSQuestion parse_dns_question(const char* buffer, size_t& offset) {
    DNSQuestion question;
    uint8_t length;

    while ((length = buffer[offset]) != 0) {
        for (int i = 0; i < length; i++) {
            question.qname.push_back(buffer[offset + i + 1]);
        }
        question.qname.push_back('.');
        offset += length + 1;
    }
    if (!question.qname.empty()) {
        question.qname.pop_back();  // Remove trailing dot
    }
    offset++;  // Skip the null byte

    memcpy(&question.qtype, buffer + offset, 2);
    question.qtype = ntohs(question.qtype);
    offset += 2;

    memcpy(&question.qclass, buffer + offset, 2);
    question.qclass = ntohs(question.qclass);
    offset += 2;

    return question;
}

size_t create_question(char* response, const DNSQuestion& question) {
    size_t offset = 0;
    size_t i = 0;
    while (i < question.qname.size()) {
        auto dot_pos = std::find(question.qname.begin() + i, question.qname.end(), '.');
        size_t length = dot_pos - (question.qname.begin() + i);
        response[offset++] = length;
        memcpy(response + offset, &question.qname[i], length);
        offset += length;
        i += length + 1;
    }
    response[offset++] = 0;  // Null terminator

    uint16_t qtype = htons(question.qtype);
    memcpy(response + offset, &qtype, 2);
    offset += 2;

    uint16_t qclass = htons(question.qclass);
    memcpy(response + offset, &qclass, 2);
    offset += 2;

    return offset;
}

size_t create_answer(char* response, const DNSQuestion& question) {
    size_t offset = create_question(response, question);

    uint32_t ttl = htonl(60);  // TTL of 60 seconds
    memcpy(response + offset, &ttl, 4);
    offset += 4;

    uint16_t rdlength = htons(4);  // Length of RDATA (4 bytes for IPv4)
    memcpy(response + offset, &rdlength, 2);
    offset += 2;

    uint32_t ip = htonl(0x08080808);  // 8.8.8.8 as an example IP
    memcpy(response + offset, &ip, 4);
    offset += 4;

    return offset;
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
            std::cerr << "Error receiving data: " << strerror(errno) << std::endl;
            continue;
        }

        if (bytesRead < sizeof(DNSHeader)) {
            std::cerr << "Received packet is too small to be a valid DNS query" << std::endl;
            continue;
        }

        DNSHeader* request_header = reinterpret_cast<DNSHeader*>(buffer);
        size_t offset = sizeof(DNSHeader);
        DNSQuestion question = parse_dns_question(buffer, offset);

        // Create DNS response
        create_dns_header(response, *request_header);
        size_t questionSize = create_question(response + sizeof(DNSHeader), question);
        size_t answerSize = create_answer(response + sizeof(DNSHeader) + questionSize, question);
        size_t responseSize = sizeof(DNSHeader) + questionSize + answerSize;

        if (sendto(udpSocket, response, responseSize, 0, 
                   reinterpret_cast<struct sockaddr*>(&clientAddress), 
                   sizeof(clientAddress)) == -1) {
            std::cerr << "Failed to send response: " << strerror(errno) << std::endl;
        }
    }

    close(udpSocket);
    return 0;
}

