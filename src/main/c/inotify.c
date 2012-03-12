#include <memory.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <net/if.h>

#include <linux/rtnetlink.h>

#include "inotify.h"

struct inotify {
    int fd;
    struct event* event;
    void* context;

    inotification_callback_t callback;
};

static
void inotify_read(evutil_socket_t fd, short type, struct inotify * context) {
    struct in_pktinfo iq;
    ssize_t len;
    char buffer[4096];
    struct nlmsghdr *nlh;

    nlh = (struct nlmsghdr *)buffer;
    while ((len = recv(fd, buffer, sizeof(buffer), 0)) > 0) {
        while ((NLMSG_OK(nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE)) {
            if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR) {
                struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nlh);
                struct rtattr *rth = IFA_RTA(ifa);
                int rtl = IFA_PAYLOAD(nlh);

                while (rtl && RTA_OK(rth, rtl)) {
                    if (rth->rta_type == IFA_LOCAL) {
                        struct inotification notification;
                        notification.type = nlh->nlmsg_type == RTM_NEWADDR ? INOTIFY_ADDR_ADDED : INOTIFY_ADDR_REMOVED;
                        notification.address.family = AF_INET;
                        notification.address.addr4.s_addr = htonl(*((uint32_t *)RTA_DATA(rth)));
                        char name[IFNAMSIZ];
                        if_indextoname(ifa->ifa_index, notification.device);
                        context->callback(context->context, &notification);
                    }
                    rth = RTA_NEXT(rth, rtl);
                }
            }
            nlh = NLMSG_NEXT(nlh, len);
        }
    }
}

struct inotify* inotify_create(struct event_base* base, void* context, inotification_callback_t callback) {
    struct inotify* inotify = malloc(sizeof(struct inotify));
    struct sockaddr_nl addr;

    inotify->fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (inotify->fd < 0) {
        fprintf(stderr, "inotify socket failed\n");
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = 0;
    addr.nl_groups = RTMGRP_IPV4_IFADDR;

    if (bind(inotify->fd, (struct sockaddr*)&addr, sizeof(addr)) <  0) {
        fprintf(stderr, "inotify bind failed\n");
        close(inotify->fd);
        return 0;
    }
    inotify->event = event_new(base, inotify->fd, EV_READ | EV_PERSIST, (event_callback_fn)inotify_read, inotify);
    if (inotify->event == 0) {
        fprintf(stderr, "event_new failed\n");
    }
    if (event_add(inotify->event, 0) < 0) {
        fprintf(stderr, "add_event failed\n");
    }
    inotify->context = context;
    return inotify;
}

void inotify_close(struct inotify* context) {
    event_del(context->event);
    event_free(context->event);
    close(context->fd);
}