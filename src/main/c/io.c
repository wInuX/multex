#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <memory.h>
#include <alloca.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "io.h"

static
void tosock(const struct udpaddress* address, struct sockaddr* sockaddr, socklen_t sockaddrlen) {
    memset(sockaddr, 0, sockaddrlen);
    if (address->ip.family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*) sockaddr;
        addr->sin_addr = address->ip.addr4;
        addr->sin_family = AF_INET;
        addr->sin_port = htons(address->port);
    } else
    if (address->ip.family == AF_INET6) {
        struct sockaddr_in6* addr = (struct sockaddr_in6*) sockaddr;
        addr->sin6_addr = address->ip.addr6;
        addr->sin6_family = AF_INET6;
        addr->sin6_scope_id = address->ip.iindex;
        addr->sin6_port = htons(address->port);
    }
}

static
void fromsock(const struct sockaddr* sockaddr, struct udpaddress* address) {
    memset(address, 0, sizeof(struct udpaddress));
    address->ip.family = sockaddr->sa_family;
    if (sockaddr->sa_family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*) sockaddr;
        address->ip.addr4 = addr->sin_addr;
        address->port = ntohs(addr->sin_port);
    } else
    if (address->ip.family == AF_INET6) {
        struct sockaddr_in6* addr = (struct sockaddr_in6*) sockaddr;
        address->ip.addr6 = addr->sin6_addr;
        address->port = ntohs(addr->sin6_port);
    }
}


int datagram_bind(struct udpaddress *address) {
    int fd, r;
    struct sockaddr_storage addr;
    int optval = 1;

    fd = socket(address->ip.family, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket failed");
        return 0;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    tosock(address, (struct sockaddr*)&addr, sizeof(addr));
    if ((r = bind(fd, (struct sockaddr*)&addr, sizeof(addr))) < 0) {
        perror("bind failed");
        close(fd);
        return r;
    }

    return fd;
}

ssize_t datagram_read(int fd, char* buf, size_t count, struct udpaddress *from) {
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    ssize_t r;
    r = recvfrom(fd, buf, count, 0, (struct sockaddr*)&addr, &addrlen);
    if (r < 0) {
        perror("recv");
    }
    if (r > 0) {
        fromsock((struct sockaddr*)&addr, from);
    }
    return r;
}

ssize_t datagram_write(int fd, char* buf, size_t count, const struct udpaddress *to) {
    struct sockaddr_storage addr;
    ssize_t r;

    tosock(to, (struct sockaddr*)&addr, sizeof(addr));
    r = sendto(fd, buf, count, 0, (struct sockaddr*)&addr, sizeof(addr));
    if (r < 0) {
        perror("write");
    }
    return r;

}

int datagram_close(int fd) {
    close(fd);
}

int ipaddress_equals(const struct ipaddress* l, const struct ipaddress* r) {
    if (l->family != r->family) {
        return 0;
    }
    if (l->family == AF_INET) {
        return memcmp(&l->addr4, &r->addr4, sizeof(l->addr4)) == 0;
    }
    if (l->family == AF_INET6) {
        return memcmp(&l->addr6, &r->addr6, sizeof(l->addr6)) == 0;
    }
    return 0;
}

int udpaddress_equals(const struct udpaddress* l, const struct udpaddress* r) {
    if (!ipaddress_equals(&l->ip, &r->ip)) {
        return 0;
    }
    return l->port == r->port;
}


int udpaddress_resolve(struct udpaddress* address, const char* host) {
    const char* phost;
    const char* pport;
    struct addrinfo hints;
    struct addrinfo* r;

    host = strdupa(host);
    char* p = strrchr(host, ':');
    if (p == 0) {
        phost = host;
        pport = "80";
    } else {
        *p = 0;
        phost = host;
        pport = p + 1;
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(phost, pport, &hints, &r) != 0) {
        fprintf(stderr, "getaddrinfo failed %s:%s\n", phost, pport);
        return 0;
    }
    fromsock(r->ai_addr, address);
    freeaddrinfo(r);
    return 1;
}

const char* udpaddress_string(const struct udpaddress* address, char* buf) {
    char addrbuf[80];

    sprintf(buf, "%s:%d", inet_ntop(address->ip.family, address->ip.family == AF_INET ? (void*)&address->ip.addr4 : (void*)&address->ip.addr6, addrbuf, sizeof(addrbuf)), address->port);
    return buf;

}