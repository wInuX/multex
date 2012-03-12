#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <memory.h>
#include <endian.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <event2/event.h>


#include "io.h"
#include "tracker.h"

#define TRACKER_NOTCONNECTED 0
#define TRACKER_CONNECTING 1
#define TRACKER_CONNECTED 2
#define TRACKER_ANNONCING 3

struct tracker;
struct session;
struct tracker_info;

struct session {
    struct session* next;
    struct tracker_info* info;

    struct tracker* tracker;
    int fd;
    struct udpaddress local;
    struct event* event;
    struct event* timer_event;
    int state;

    uint64_t connectionid;
    uint32_t transactionid;
};


struct tracker_info {
    struct tracker_info* next;

    struct udpaddress remote;
};

struct tracker {
    struct event_base* event_base;
    void* context;
    tracker_callback_t callback;

    struct session sessions;
    struct tracker_info trackers;
};

#pragma pack(push, 1)

struct connect_request {
    uint64_t connection_id;
    uint32_t action;
    uint32_t transaction_id;
};

struct connect_response {
    uint32_t action;
    uint32_t transaction_id;
    uint64_t connection_id;
};

struct announce_request {
    uint64_t connection_id;
    uint32_t action;
    uint32_t transaction_id;
    uint8_t info_hash[20];
    uint8_t peer_id[20];
    uint64_t downloaded;
    uint64_t left;
    uint64_t uploaded;
    uint32_t event;
    uint32_t ip;
    uint32_t key;
    int32_t num_want;
    uint16_t port;
    /*uint16_t extensions;*/
};

struct announce_response {
    uint32_t action;
    uint32_t transaction_id;
    uint32_t interval;
    uint32_t leechers;
    uint32_t seeders;
};

struct peer_info {
    uint32_t ip;
    uint16_t port;
};

#pragma pack(pop)

static
void write_connect(struct session* session) {
    struct connect_request request;
    struct timeval timeval;

    request.connection_id = htobe64(0x0000041727101980LL);
    request.action = htobe32(0);
    request.transaction_id = htobe32( session->transactionid = random());

    datagram_write(session->fd, (char*)&request, sizeof(request), &session->info->remote);
    session->state = TRACKER_CONNECTING;

    timeval.tv_sec = 10;
    timeval.tv_usec = 0;
    evtimer_add(session->timer_event, &timeval);

    fprintf(stderr, "!!tracker write_connect sent\n");
}

static
void write_announce(struct session* session) {
    struct announce_request request;
    struct timeval timeval;

    request.connection_id = htobe64(session->connectionid);
    request.action = htobe32(1);
    request.transaction_id = htobe32( session->transactionid = random());
    memset(&request.info_hash, 1, sizeof(request.info_hash));
    memset(&request.peer_id, 1, sizeof(request.peer_id));
    memcpy(&request.peer_id, "-TR0102-", 8);
    request.downloaded = 0;
    request.left = htobe64(0);
    request.uploaded = 0;
    request.event = 0;
    request.ip = 0;
    request.port = 11;
    request.num_want = htobe32(10);
    request.key = htobe32(random());
    /*request.extensions = 0;*/

    datagram_write(session->fd, (char*)&request, sizeof(request), &session->info->remote);
    session->state = TRACKER_ANNONCING;

    timeval.tv_sec = 10;
    timeval.tv_usec = 0;
    evtimer_add(session->timer_event, &timeval);
    fprintf(stderr, "!!tracker write_scrape sent\n");

}

static
void read_connect(struct session* session, char* data, ssize_t count) {
    struct connect_response *response = (struct connect_response*) data;

    if (count < sizeof(struct connect_response)) {
        return;
    }
    fprintf(stderr, "!!tracker read_connect\n");
    session->connectionid = be64toh(response->connection_id);
    session->state = TRACKER_CONNECTED;
    write_announce(session);
}

static
void read_announce(struct session* session, char* data, ssize_t count) {
    struct announce_response *response = (struct announce_response*)data;
    struct peer_info* peer =  (struct peer_info*)(data + sizeof(struct announce_response));
    int peer_count = (count - sizeof(struct announce_response)) / sizeof(struct peer_info);
    struct timeval timeval;

    fprintf(stderr, "!!tracker read_announce\n");
    if (count < sizeof(struct announce_response)) {
        return;
    }
    fprintf(stderr, "Announce received");
    while (peer_count-- > 0) {
        struct udpaddress addr;
        char buf[INET_ADDRSTRLEN];

        memset(&addr, 0, sizeof(addr));
        addr.ip.family = AF_INET;
        addr.ip.addr4.s_addr = peer->ip;
        addr.port = ntohs(peer->port);

        session->tracker->callback(session->tracker->context, &addr, be32toh(response->interval));        
    }
    session->state = TRACKER_CONNECTED;
    timeval.tv_sec = be32toh(response->interval);
    if (timeval.tv_sec > 1200) {
        timeval.tv_sec = 1200;
    }
    timeval.tv_usec = 0;
    fprintf(stderr, "!!tracker read_announce timeout: %d\n", (int)timeval.tv_sec);
    evtimer_add(session->timer_event, &timeval);
}

static
void timeout_callback(evutil_socket_t fd, short type, struct session* session) {
    struct timeval timeval;

    fprintf(stderr, "!!tracker timeout_callback\n");
    switch (session->state) {
         case TRACKER_CONNECTED:
             write_announce(session);
             break;
         case TRACKER_NOTCONNECTED:
             write_connect(session);
             break;
         case TRACKER_CONNECTING:
         case TRACKER_ANNONCING:
             timeval.tv_sec = 30;
             timeval.tv_usec = 0;
             session->state = TRACKER_NOTCONNECTED;
             evtimer_add(session->timer_event, &timeval);
             break;
    }
}

static
void socket_callback(evutil_socket_t fd, short type, struct session* session) {
    struct udpaddress from;
    char buf[1500];
    ssize_t length;

    fprintf(stderr, "!!tracker socket_callback\n");
    length = datagram_read(fd, buf, sizeof(buf), &from);
    if (length < 0) {
        return;
    }
    switch (session->state) {
         case TRACKER_NOTCONNECTED:
         case TRACKER_CONNECTED:
            break;
         case TRACKER_CONNECTING:
            read_connect(session, buf, length);
            break;
         case TRACKER_ANNONCING:
            read_announce(session, buf, length);
            break;
    }
}


struct tracker* tracker_create(struct event_base* event_base, void* context, tracker_callback_t callback) {
    struct tracker* tracker = malloc(sizeof(struct tracker));

    tracker->context = context;
    tracker->callback = callback;
    tracker->event_base = event_base;

    tracker->sessions.next = &tracker->sessions;
    tracker->trackers.next = &tracker->trackers;

    return tracker;
}

void tracker_add(struct tracker* tracker, const char* host) {
    struct tracker_info *info = malloc(sizeof(struct tracker_info));

    if (udpaddress_resolve(&info->remote, host) == 0) {
        return;
    }
    info->next = tracker->trackers.next;
    tracker->trackers.next = info;
}

void tracker_add_endpoint(struct tracker* tracker, struct ipaddress* local) {
    struct tracker_info *info = tracker->trackers.next;

    while (info != &tracker->trackers) {
        struct session* session = malloc(sizeof(struct session));

        if (local->family != info->remote.ip.family) {
            info = info->next;
            continue;
        }
        session->tracker = tracker;
        session->local.ip = *local;
        session->local.port = 49001;
        session->fd = datagram_bind(&session->local);
        session->info = info;
        if (session->fd < 0) {
            perror("tracker bind failed");
            free(session);
            return;
        }
        session->state = TRACKER_NOTCONNECTED;
        session->event = event_new(tracker->event_base, session->fd, EV_READ | EV_PERSIST, (event_callback_fn)socket_callback, session);
        event_add(session->event, 0);
        session->timer_event = evtimer_new(tracker->event_base, (event_callback_fn)timeout_callback, session);

        write_connect(session);

        session->next = tracker->sessions.next;
        tracker->sessions.next = session;
        info = info->next;
    }
}

void tracker_remove_endpoint(struct tracker* tracker, struct ipaddress* local) {
    struct session* p;

    p = &tracker->sessions;
    while (p->next != &tracker->sessions) {
        struct session* session = p->next;;
        if (ipaddress_equals(local, &session->next->local.ip) == 0) {
            datagram_close(session->fd);
            p->next = session->next;
            free(session);
            continue;
        }
        p = p->next;
    }
}

void tracker_close(struct tracker* tracker) {
    free(tracker);
}
