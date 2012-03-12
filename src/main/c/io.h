#ifndef _M_IO_H_
#define _M_IO_H_

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

struct ipaddress {
    sa_family_t family; /*AF_INET, AF_INET6*/

    int iindex;
    struct in_addr addr4;
    struct in6_addr addr6;
};

struct udpaddress {
    struct ipaddress ip;
    in_port_t port;
};

#define SELECT_MAX 100

struct selectcontext {
    int fd[SELECT_MAX];
    int type[SELECT_MAX];

    int count;
};

int datagram_bind(struct udpaddress *address);

ssize_t datagram_read(int fd, char* buf, size_t count, struct udpaddress *from);
ssize_t datagram_write(int fd, char* buf, size_t count, const struct udpaddress *to);

int datagram_close(int fd);

int ipaddress_equals(const struct ipaddress* l, const struct ipaddress* r);

int udpaddress_equals(const struct udpaddress* l, const struct udpaddress* r);

int udpaddress_resolve(struct udpaddress* address, const char* host);

const char* udpaddress_string(const struct udpaddress* address, char* buf);
#endif