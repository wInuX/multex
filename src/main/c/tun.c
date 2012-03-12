#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include "tun.h"

int tun_open(const char *dev) {

    struct sockaddr_ll addr;
    struct ifreq ifr;
    int fd, err;

    if( (fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0 ) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy (ifr.ifr_name, dev, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        fprintf(stderr, "Can't query interface.\n");
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Can't bind interface.\n");
        close(fd);
        return -1;

    }
    return fd;
}

int tun_create(const char *dev) {

    struct ifreq ifr;
    int fd, err;

    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
        perror("tun open failed");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
        perror("tun ioctl failed");
        close(fd);
        return err;
    }
    return fd;
}



ssize_t tun_read(int fd, char* buf, size_t count) {
    char ibuf[1504];
    ssize_t r;

    r = read(fd, buf, count + 4);
    if (r < 0) {
        return r;
    }
    memcpy(buf, ibuf + 4, r - 4);
    return r >= 4 ? r - 4 : 0;
}


ssize_t tun_write(int fd, char* ibuf, size_t count) {
    char buf[1504];
    ssize_t r;

    memcpy(buf + 4, ibuf, count);
    buf[0] = 0;
    buf[1] = 0;
    buf[2] = 0x86;
    buf[3] = 0xdd;
    r = write(fd, buf, count + 4);
    if (r >= 4) {
        r -= 4;
    }
    return r;
}


void tun_close(int fd) {
    close(fd);
}
