#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <alloca.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <time.h>

/*#include <linux/if.h>*/
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <ifaddrs.h>

#include <event2/event.h>

#include "io.h"
#include "tun.h"
#include "inotify.h"
#include "tracker.h"
#include "cipher.h"
#include "proto.h"

struct master_config;
struct interface;
struct endpoint;
struct remote_endpoint;
struct session;

struct hwaddress {
    unsigned char data[6];
};

#define TYPE_ACTIVE 1
#define TYPE_PASSIVE 2

struct interface {
    struct interface* next;

    char* name;

    int active;
    int priority;
    int weight;
};

struct endpoint {
    struct endpoint* next;
    struct interface* interface;
    struct master_config* config;

    int socket;
    struct event* event;

    struct udpaddress local;
};

typedef unsigned long long utime_t;

struct remote_endpoint {
    struct remote_endpoint* next;

    struct udpaddress remote;
    utime_t lastseen;
    utime_t expiration;    
};

struct association;

struct association {
    struct association* next;
    struct endpoint* endpoint;
    struct remote_endpoint* rendpoint;

    utime_t lastconnect;
};

struct session {
    struct session* next;
    struct endpoint* endpoint;
    struct remote_endpoint* rendpoint;
    struct association* association;
    struct master_config* config;
    int type;
    int priority;

    utime_t last;

    struct hwaddress hwremote;

    struct cipher_context* rkey; /*key used to send requests*/

    struct cipher_context* key1; /*our key*/
    struct cipher_context* key2; /*our new key*/
};

struct master_config {
    struct event_base * event_base;
    struct event* master_event;
    struct event* stdin_event;
    char* trackerhost;
    struct tracker* tracker;

    int master_fd;
    int port;
    struct inotify *inotify;

    struct interface interfaces;
    struct endpoint endpoints;
    struct remote_endpoint rendpoints;
    struct session sessions;
    struct association associations;

    struct hwaddress hwlocal;

    struct cipher_context* key0; /* protocol negotiation */
    struct cipher_context* keyX; /* our secret key*/
    struct digest_context* digest;
    int digest_size;
    int cipher_size;
    int cipher_keysize;

    struct cipher* cipher;
};

static struct endpoint* endpoint_find_by_address(struct master_config* config, const struct udpaddress* address);
static struct association* association_find_by_address(struct master_config* config, const struct udpaddress* local, const struct udpaddress* remote);

static struct remote_endpoint* rendpoint_add(struct master_config* config, struct udpaddress* address);
static struct remote_endpoint* rendpoint_find_by_address(struct master_config* config, const struct udpaddress* address);

static struct session* session_find_by_address(struct master_config* config, const struct udpaddress* local, const struct udpaddress* remote);
static struct session* session_create(struct master_config* config, struct endpoint* endpoint, struct remote_endpoint* rendpoint);

static struct remote_endpoint* rendpoint_update(struct master_config* config, struct udpaddress* remote, utime_t timeout);
static struct endpoint* endpoint_update(struct master_config* config, struct interface* interface, struct udpaddress* local);
static struct association* association_update(struct master_config* config, struct endpoint* endpoint, struct remote_endpoint* rendpoint);

static
int hwaddress_isbroadcast(const struct hwaddress* addr) {
    return addr->data[0] & 1;
}

utime_t now() {
    struct timespec timespec;
    clock_gettime(CLOCK_REALTIME, &timespec);
    return (utime_t)timespec.tv_sec * 1000  + timespec.tv_nsec / 1000000;
}

static
ssize_t xdecrypt(struct master_config* config, struct cipher_context* context, const char* in, size_t ilength, char* out) {
    char* tmp;
    char* signature;
    ssize_t olength, i;

    if (ilength < config->digest_size) {
        return -1;
    }

    tmp = alloca(ilength - config->digest_size);
    signature = alloca(config->digest_size);

    olength = cipher_decrypt(context, in, ilength - config->digest_size, tmp);
    if (olength < config->cipher_size) {
        fprintf(stderr, "invalid packet. %d\n", (int)olength);
        return -1;
    }

    digest_sign(config->digest, tmp, olength, signature);
    if (memcmp(signature, in + ilength - config->digest_size, config->digest_size) != 0) {
        /*fprintf(stderr, "signature mistmatch\n");*/
        return -1;
    }
    memcpy(out, tmp + config->cipher_size, olength - config->cipher_size);
    return olength - config->cipher_size;
}

static
ssize_t xencrypt(struct master_config* config, struct cipher_context* context, const char* in, size_t ilength, char* out) {
    char* tmp;
    ssize_t r,i;

    tmp = alloca(ilength + config->cipher_size);
    random_bytes(tmp, config->cipher_size);
    memcpy(tmp + config->cipher_size, in, ilength);

    r = cipher_encrypt(context, tmp, ilength + config->cipher_size, out);

    digest_sign(config->digest, tmp, ilength + config->cipher_size, out + r);
    return r + config->digest_size;
}

struct rcontext {
    struct master_config* config;
    struct endpoint* endpoint;
    struct remote_endpoint* rendpoint;
    struct session* session;

    struct udpaddress from;

    struct cipher_context* rkey;
    struct proto proto;
};

static
ssize_t create_challenge(struct master_config* config, struct udpaddress* remote, struct udpaddress* local, const char* newkey, const char* oldkey, char* obuf) {
    char* p = obuf;
    memcpy(p, newkey, config->cipher_keysize);
    p += config->cipher_keysize;
    memcpy(p, oldkey, config->cipher_keysize);
    p += config->cipher_keysize;
    if (remote->ip.family == AF_INET) {
        *p++ = 0;
        *(uint32_t*)p = remote->ip.addr4.s_addr;
        p += 4;
        *(uint32_t*)p = local->ip.addr4.s_addr;
        p += 4;
    } else if (remote->ip.family == AF_INET6) {
        *p++ = 1;
        memcpy(p, &remote->ip.addr6, 16);
        p += 16;
        memcpy(p, &local->ip.addr6, 16);
        p += 16;
    } else {
        assert(0);
    }
    *(uint16_t*)p = htons(remote->port);
    p += 2;
    *(uint16_t*)p = htons(local->port);
    p += 2;
    return p - obuf;
}

static
ssize_t encrypt_challenge(struct master_config* config, struct udpaddress* remote, struct udpaddress* local, const char* newkey, const char* oldkey, char* obuf) {
    char token[1500];
    size_t tlength;

    tlength = create_challenge(config, remote, local, newkey, oldkey, token);
    return xencrypt(config, config->keyX, token, tlength, obuf);
}

struct cipher_context* verify_challenge(struct master_config* config, struct udpaddress* remote, struct udpaddress* local, char* in, ssize_t ilength) {
    char obuf[1500];
    char token[1500];
    ssize_t tlength, olength;
    struct session* session;
    struct cipher_context* oldkey = config->key0;

    session = session_find_by_address(config, local, remote);
    if (session) {
        if (session->key1) {
            oldkey = session->key1;
        }
    }

    olength = xdecrypt(config, config->keyX, in, ilength, obuf);
    if (olength < 0) {
        return 0;
    }
    tlength = create_challenge(config, remote, local, obuf, cipher_context_getkey(oldkey), token);

    if (tlength != olength) {
        return 0;
    }

    if (memcmp(token, obuf, tlength) != 0) {
        return 0;
    }
    return cipher_context_create(config->cipher, obuf);
}

static
void encrypt_and_write(struct master_config* config, int fd, const struct udpaddress* address, struct cipher_context* key, const char* ibuf, ssize_t ilength) {
    char sbuf[1500], buf[128];
    ssize_t slength;

    slength = xencrypt(config, key, ibuf, ilength, sbuf);
    fprintf(stderr, "!!writing %d bytes to %s\n", (int) slength, udpaddress_string(address, buf));
    if (datagram_write(fd, sbuf, slength, address) < 0) {
        fprintf(stderr, "write_offer datagram_write failed. Address: %s\n", udpaddress_string(address, buf));
    }
}

static
void write_offer(struct master_config* config, struct endpoint* endpoint, struct udpaddress* remote) {
    char* key;
    char token[1500];
    char obuf[1500];
    ssize_t tlength, olength, r;
    struct proto proto;
    struct session* session;
    struct cipher_context* oldkey = config->key0, *rkey = config->key0;

    key = alloca(config->cipher_keysize);
    random_bytes(key, config->cipher_keysize);


    session = session_find_by_address(config, &endpoint->local, remote);
    if (session) {
        if (session->key1) {
            oldkey = session->key1;
        }
        if (session->rkey) {
            rkey = session->rkey;
        }
    }

    tlength = encrypt_challenge(config, remote, &endpoint->local, key, cipher_context_getkey(oldkey), token);

    memset(&proto, 0, sizeof(proto));
    proto.type = PROTO_OFFER;
    proto.id.value = token;
    proto.id.length = tlength;
    proto.key.value = key;
    proto.key.length = config->cipher_keysize;
    olength = proto_encode(&proto, obuf, sizeof(obuf));

    encrypt_and_write(config, endpoint->socket, remote, rkey, obuf, olength);
}

static
void write_challenge(struct rcontext* rcontext, const char* key) {
    char token[1500];
    char obuf[1500];
    struct proto proto;
    struct cipher_context *old = 0;

    ssize_t tlength, olength;

    memset(&proto, 0, sizeof(proto));

    tlength = encrypt_challenge(rcontext->config, &rcontext->from, &rcontext->endpoint->local, key, cipher_context_getkey(rcontext->rkey), token);
    proto.type = PROTO_CHALLENGE;
    proto.id.value = token;
    proto.id.length = tlength;
    if (rcontext->proto.id.length) {
        proto.rid.value = rcontext->proto.id.value;
        proto.rid.length = rcontext->proto.id.length;
    }
    olength = proto_encode(&proto, obuf, sizeof(obuf));
    encrypt_and_write(rcontext->config, rcontext->endpoint->socket, &rcontext->from, rcontext->rkey, obuf, olength);
}

static
void read_offer(struct rcontext* rcontext, const struct proto* proto) {
    char obuf[1500], token[1600], sbuf[1700];
    char* p = obuf;
    ssize_t tlength, slength;

    if (proto->key.length != rcontext->config->cipher_keysize) {
        return;
    }
    write_challenge(rcontext, proto->key.value);
}

static
void write_confirm(struct rcontext* rcontext, const char* token, ssize_t tlength) {
    char obuf[1500];
    ssize_t olength;
    struct proto proto;

    memset(&proto, 0, sizeof(proto));

    proto.type = PROTO_CONFIRM;
    proto.rid.value = rcontext->proto.id.value;
    proto.rid.length = rcontext->proto.id.length;

    proto.parameters.priority = rcontext->endpoint->interface->priority;
    proto.parameters.weight = rcontext->endpoint->interface->weight;

    olength = proto_encode(&proto, obuf, sizeof(obuf));

    encrypt_and_write(rcontext->config, rcontext->endpoint->socket, &rcontext->from, rcontext->rkey, obuf, olength);
}

static
void read_challenge(struct rcontext* rcontext, const struct proto* proto) {
    struct cipher_context* key2;

    key2 = verify_challenge(rcontext->config, &rcontext->from, &rcontext->endpoint->local, proto->rid.value, proto->rid.length);
    if (key2) {
        if (rcontext->session == 0) {
            fprintf(stderr, "Challenge accepted. Creating new session\n");
            rcontext->session = session_create(rcontext->config, rcontext->endpoint, rcontext->rendpoint);
        }
        rcontext->session->key2 = key2;
        write_confirm(rcontext, proto->id.value, proto->id.length);
    } else {
        fprintf(stderr, "Challenge verify failed\n");
    }
}

static
void write_accept(struct rcontext* rcontext) {
    char obuf[1500];
    ssize_t olength;
    struct proto proto;

    memset(&proto, 0, sizeof(proto));

    proto.type = PROTO_ACCEPTED;
    proto.rid.value = rcontext->proto.id.value;
    proto.rid.length = rcontext->proto.id.length;
    olength = proto_encode(&proto, obuf, sizeof(obuf));

    encrypt_and_write(rcontext->config, rcontext->endpoint->socket, &rcontext->from, rcontext->rkey, obuf, olength);
}

static
void read_confirm(struct rcontext* rcontext, const struct proto* proto) {
    char buf[1500];
    ssize_t olength = 0;
    struct cipher_context *cipher;
    olength = xdecrypt(rcontext->config, rcontext->config->keyX, proto->rid.value, proto->rid.length, buf);
    if (olength < 0) {
        return;
    }
    cipher = verify_challenge(rcontext->config, &rcontext->from, &rcontext->endpoint->local, proto->rid.value, proto->rid.length);
    if (cipher == 0) {
        fprintf(stderr, "!! verify_challenge failed\n");
        return;
    }
    /* update session*/
    if (rcontext->rendpoint == 0) {
        rcontext->rendpoint = rendpoint_update(rcontext->config, &rcontext->from, 0);
    }

    if (rcontext->session == 0) {
        fprintf(stderr, "Confirm accepted. Creating new session\n");
        rcontext->session = session_create(rcontext->config, rcontext->endpoint, rcontext->rendpoint);
    } else {
        fprintf(stderr, "confirm accepted\n");
    }
    if (rcontext->session->rkey) {
        cipher_context_free(rcontext->session->rkey);
    }
    rcontext->session->rkey = cipher_context_create(rcontext->config->cipher, buf);
    write_accept(rcontext);
    if (rcontext->session->key1 == 0) {
        write_offer(rcontext->config, rcontext->endpoint, &rcontext->from);
    }
}

static
void read_accept(struct rcontext* rcontext, const struct proto* proto) {
    if (rcontext->session == 0) {
        return;
    }
    if (rcontext->session->key1) {
        cipher_context_free(rcontext->session->key1);
    }
    rcontext->session->key1 = rcontext->session->key2;
    rcontext->session->key2 = 0;
}

static
void read_data(struct rcontext* rcontext, const struct proto* proto) {
    tun_write(rcontext->config->master_fd, proto->data.value, proto->data.length);
}

static
void write_data(struct master_config* config, struct session* session, const char* ibuf, ssize_t ilength) {
    struct proto proto;
    char obuf[1500];
    ssize_t olength;

    memset(&proto, 0, sizeof(proto));
    proto.type = PROTO_DATA;
    proto.data.value = (char*)ibuf;
    proto.data.length = ilength;

    olength = proto_encode(&proto, obuf, sizeof(obuf));

    encrypt_and_write(config, session->endpoint->socket, &session->rendpoint->remote, session->rkey, obuf, olength);
}

void master_callback(evutil_socket_t fd, short type, struct master_config* config) {
    char ibuf[1500];
    ssize_t ilength;
    struct session* session;


    ilength = tun_read(fd, ibuf, sizeof(ibuf));
    if (ilength < 0) {
        return;
    }

    session = config->sessions.next;
    while (session != &config->sessions) {
        if (session->rkey == 0) {
            session = session->next;
            continue;
        }
        if (hwaddress_isbroadcast((struct hwaddress*)ibuf)) {
            write_data(config, session, ibuf, ilength);        
        } else {
            if (memcmp(&session->hwremote, ibuf, 6) == 0) {
                write_data(config, session, ibuf, ilength);
                /*TODO*/
                return;
            }
        }
        session = session->next;
    }
    fprintf(stderr, "!!no session with hwaddr\n");
}

void stdin_callback(evutil_socket_t fd, short type, struct master_config* config) {
    char ibuf[1500];
    ssize_t ilength;
    while ((ilength = read(STDIN_FILENO, ibuf, sizeof(ibuf))) > 0) {
        ;
    }
    {
        struct interface* interface = config->interfaces.next;
        fprintf(stderr, "Interfaces: \n");
        while (interface != &config->interfaces) {
            fprintf(stderr, " %s\n", interface->name);
            interface = interface->next;
        }
    }
    {
        struct endpoint* endpoint = config->endpoints.next;
        char buf[128];

        fprintf(stderr, "Endpoints: \n");
        while (endpoint != &config->endpoints) {
            fprintf(stderr, " %d: %s \n", endpoint->socket, udpaddress_string(&endpoint->local, buf));            
            endpoint = endpoint->next;
        }
    }
    {
        struct remote_endpoint* rendpoint = config->rendpoints.next;
        char buf[128];

        fprintf(stderr, "Remotes: \n");
        while (rendpoint != &config->rendpoints) {
            fprintf(stderr, " %s \n", udpaddress_string(&rendpoint->remote, buf));
            rendpoint = rendpoint->next;
        }
    }
    {
        struct session* session = config->sessions.next;
        char buf1[128], buf2[128];

        fprintf(stderr, "Sessions: \n");
        while (session != &config->sessions) {
            fprintf(stderr, " %s <=> %s. local: %d. remote: %d\n", udpaddress_string(&session->endpoint->local, buf1), udpaddress_string(&session->rendpoint->remote, buf2), session->key1 != 0, session->key2 != 0);
            session = session->next;
        }
    }
}

void interface_socket_callback(evutil_socket_t fd, short type, struct endpoint* endpoint) {
    struct rcontext rcontext;
    char ibuf[1500];
    char obuf[1500];
    char buf1[128], buf2[128];
    ssize_t ilength, olength;
    struct master_config* config = endpoint->config;

    ilength = datagram_read(fd, ibuf, sizeof(ibuf), &rcontext.from);
    if (ilength < 0) {
        return;
    }
    if (udpaddress_equals(&endpoint->local, &rcontext.from)) {
        return;
    }
    rcontext.endpoint = endpoint;
    rcontext.rendpoint = rendpoint_find_by_address(config, &rcontext.from);
    rcontext.session = session_find_by_address(endpoint->config, &endpoint->local, &rcontext.from);
    rcontext.config = config;

    fprintf(stderr, "read %d bytes %s <=> %s. session: %d, rendpoint: %d\n", (int)ilength, udpaddress_string(&rcontext.from, buf1), udpaddress_string(&endpoint->local, buf2), rcontext.session != 0, rcontext.rendpoint != 0);

    olength = -1;
    if (rcontext.session) {
        if (rcontext.session->key1) {
            rcontext.rkey = rcontext.session->key1;
            olength = xdecrypt(config, rcontext.session->key1, ibuf, ilength, obuf);
            if (olength > 0) {
                fprintf(stderr, "!!key1\n");
            }
        }
        if (olength < 0 && rcontext.session->key2) {
            rcontext.rkey = rcontext.session->key2;
            olength = xdecrypt(config, rcontext.session->key2, ibuf, ilength, obuf);
            if (olength > 0) {
                fprintf(stderr, "!!key2\n");
            }
        }
    }
    if (olength < 0) {
        rcontext.rkey = config->key0;
        olength = xdecrypt(config, config->key0, ibuf, ilength, obuf);
        if (olength > 0) {
            fprintf(stderr, "!!key0\n");
        }
    }
    if (olength < 0) {
        fprintf(stderr, "!!decrypt failed\n");
        return;
    }
    if (proto_decode(&rcontext.proto, obuf, olength) <= 0) {
        fprintf(stderr, "!!decode failed\n");
        return;
    }

    switch (rcontext.proto.type) {
        case PROTO_OFFER:
            fprintf(stderr, "!!Received offer\n");
            // key change
            read_offer(&rcontext, &rcontext.proto);
            break;
        case PROTO_CHALLENGE:
            fprintf(stderr, "!!Received challenge\n");
            read_challenge(&rcontext, &rcontext.proto);
            break;
        case PROTO_CONFIRM:
            // key change confirmed
            fprintf(stderr, "!!Received confirm\n");
            read_confirm(&rcontext, &rcontext.proto);
            break;
        case PROTO_ACCEPTED:
            fprintf(stderr, "!!Received accepted\n");
            read_accept(&rcontext, &rcontext.proto);
            break;
        case PROTO_DATA:
            fprintf(stderr, "!!Received data\n");
            if (rcontext.session == 0) {
                break;
            }
            if (rcontext.rkey == config->key0) {
                break;
            }
            read_data(&rcontext, &rcontext.proto);
            break;
        default:
            assert(0);
            break;
    }
}

void inotify_callback(struct master_config* config, struct inotification* n) {
    char buf[100];
    switch (n->type) {
        case INOTIFY_INT_ADDED:
            fprintf(stderr, "Interface added %s\n", n->device);
            break;
        case INOTIFY_INT_REMOVED:
            fprintf(stderr, "Interface removed %s\n", n->device);
            break;
        case INOTIFY_ADDR_ADDED: {
            struct interface* interface = config->interfaces.next;
            struct association* association;
            struct udpaddress address;

            while (interface != &config->interfaces) {
                if (strcmp(interface->name, n->device) == 0) {
                    break;
                }
                interface = interface->next;
            }

            if (interface == &config->interfaces) {
                break;
            }

            fprintf(stderr, "Address added on %s: %s\n", n->device,
                inet_ntop(n->address.family, n->address.family == AF_INET ? (void*)&n->address.addr4 : (void*)&n->address.addr6, buf, sizeof(buf))
            );
            address.ip = n->address;
            address.port = config->port;
            address.ip.iindex = if_nametoindex(n->device);
            endpoint_update(config, interface, &address);
            tracker_add_endpoint(config->tracker, &address.ip);
            break;
        }
        default:
            fprintf(stderr, "!! inotify\n");
            break;
    }

}

static
struct endpoint* endpoint_find_by_address(struct master_config* config, const struct udpaddress* address) {
    struct endpoint* endpoint = config->endpoints.next;
    while (endpoint != &config->endpoints) {
        if (udpaddress_equals(&endpoint->local, address)) {
            return endpoint;
        }
        endpoint = endpoint->next;
    }
    return 0;
}

static
struct remote_endpoint* rendpoint_find_by_address(struct master_config* config, const struct udpaddress* address) {
    struct remote_endpoint* rendpoint = config->rendpoints.next;
    while (rendpoint != &config->rendpoints) {
        if (udpaddress_equals(&rendpoint->remote, address)) {
            return rendpoint;
        }
        rendpoint = rendpoint->next;
    }
    return 0;
}

static
struct session* session_find_by_address(struct master_config* config, const struct udpaddress* local, const struct udpaddress* remote) {
    struct session* session = config->sessions.next;
    while (session != &config->sessions) {
        if (udpaddress_equals(&session->endpoint->local, local) && udpaddress_equals(&session->rendpoint->remote, remote)) {
            return session;
        }
        session = session->next;
    }
    return 0;
}

static
struct association* association_find_by_address(struct master_config* config, const struct udpaddress* local, const struct udpaddress* remote) {
    struct association* association = config->associations.next;
    while (association != config->associations.next) {
        if (udpaddress_equals(&association->endpoint->local, local) && udpaddress_equals(&association->rendpoint->remote, remote)) {
            return association;
        }
        association = association->next;
    }
    return 0;
}

static
struct session* session_create(struct master_config* config, struct endpoint* endpoint, struct remote_endpoint* rendpoint) {
    struct session* session = malloc(sizeof(struct session));

    session->endpoint = endpoint;
    session->rendpoint = rendpoint;
    session->rkey = 0;
    session->key1 = 0;
    session->key2 = 0;

    session->next = config->sessions.next;
    config->sessions.next = session;

    return session;
}

static
struct remote_endpoint* rendpoint_add(struct master_config* config, struct udpaddress* address) {
    struct remote_endpoint* rendpoint = config->rendpoints.next;

    while (rendpoint != &config->rendpoints) {
        if (udpaddress_equals(&rendpoint->remote, address)) {
            return rendpoint;
        }
        rendpoint = rendpoint->next;
    }
    rendpoint = malloc(sizeof(struct remote_endpoint));
    rendpoint->remote = *address;
    rendpoint->next = config->rendpoints.next;
    config->rendpoints.next = rendpoint;
    return rendpoint;
}




void tracker_callback(struct master_config* config, struct udpaddress* address, utime_t timeout) {
    rendpoint_update(config, address, timeout);
}

static struct remote_endpoint* rendpoint_update(struct master_config* config, struct udpaddress* address, utime_t timeout) {
    struct endpoint* endpoint;
    struct remote_endpoint* rendpoint;
    char buf[128];

    rendpoint = rendpoint_find_by_address(config, address);
    if (rendpoint == 0) {
        fprintf(stderr, "Remote endpoint discovered %s\n", udpaddress_string(address, buf));

        rendpoint = malloc(sizeof(struct remote_endpoint));
        rendpoint->remote = *address;
        rendpoint->lastseen = now();
        rendpoint->expiration = timeout;

        rendpoint->next = config->rendpoints.next;
        config->rendpoints.next = rendpoint;
    }
    /* for each endpoint update association */
    endpoint = config->endpoints.next;
    while (endpoint != &config->endpoints) {
        association_update(config, endpoint, rendpoint);
        endpoint = endpoint->next;
    }
}

static
struct endpoint* endpoint_update(struct master_config* config, struct interface* interface, struct udpaddress* address) {
    struct endpoint* endpoint;
    struct remote_endpoint* rendpoint;
    char buf[128];

    endpoint = endpoint_find_by_address(config, address);
    if (endpoint == 0) {
        endpoint = malloc(sizeof(struct endpoint));

        endpoint->config = config;
        endpoint->interface = interface;
        endpoint->local = *address;
        endpoint->socket = datagram_bind(address);
        if (endpoint->socket < 0) {
            perror("multex bind failed");
            return 0;
        }
        endpoint->event = event_new(config->event_base, endpoint->socket, EV_READ | EV_PERSIST, (event_callback_fn)interface_socket_callback, endpoint);
        event_add(endpoint->event, 0);

        endpoint->next = config->endpoints.next; 
        config->endpoints.next = endpoint;
    }
    /* for each rendpoint update association */
    rendpoint = config->rendpoints.next;
    while (rendpoint != &config->rendpoints) {
        association_update(config, endpoint, rendpoint);
        rendpoint = rendpoint->next;
    }
}

static
struct association* association_update(struct master_config* config, struct endpoint* endpoint, struct remote_endpoint* rendpoint) {
    struct association* association;

    if (endpoint->local.ip.family != rendpoint->remote.ip.family) {
        return 0;    
    }
    if (udpaddress_equals(&endpoint->local, &rendpoint->remote)) {
        /* do not create self association*/
        return 0;
    }

    association = association_find_by_address(config, &endpoint->local, &rendpoint->remote);
    if (association == 0) {
        association = malloc(sizeof(struct association));
        association->endpoint = endpoint;
        association->rendpoint = rendpoint;
        association->lastconnect = now();
        write_offer(config, endpoint, &rendpoint->remote);

        association->next = config->associations.next;
        config->associations.next = association;
    }
    return association;
}


int ENTRY_NAME(int argc, const char* argv[]) {
    const char **p = alloca(argc * sizeof(char*));
    struct master_config config;
    char* keybuf;

    memcpy(p, argv + 1, (argc - 1) * sizeof(char*));
    p[argc - 1] = 0;

    if (--argc == 0) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "\tmultex --dev <name> --interface <name> \n");
        return 2;
    }

    config.interfaces.next = &config.interfaces;
    config.sessions.next = &config.sessions;
    config.endpoints.next = &config.endpoints;
    config.rendpoints.next = &config.rendpoints;
    config.associations.next = &config.associations;
    config.port = 1389;
    config.event_base = event_base_new();
    config.tracker = tracker_create(config.event_base, &config, (tracker_callback_t)tracker_callback);
    if (config.tracker == 0) {
        return 1;
    }

    config.cipher = cipher_bf();
    config.cipher_keysize = cipher_keysize(config.cipher);
    config.cipher_size = cipher_blocksize(config.cipher);
    keybuf = alloca(config.cipher_keysize);

    config.trackerhost = "tracker.publicbt.com:80";
    memset(keybuf, 0, config.cipher_keysize);
    config.key0 = cipher_context_create(config.cipher, keybuf);
    random_bytes(keybuf, config.cipher_keysize);
    config.keyX = cipher_context_create(config.cipher, keybuf);

    config.digest = digest_context_create(digest_sha());
    config.digest_size = digest_size(digest_sha());

    while (*p != 0) {
        const char* cmd = *p++;
        if (strcmp(cmd, "--tracker") == 0) {
            if (*p == 0) {
                fprintf(stderr, "tracker address expected\n");
                return 2;
            }
            tracker_add(config.tracker, *p++);
            continue;
        }
        if (strcmp(cmd, "--remote") == 0) {
            struct udpaddress address;
            if (*p == 0) {
                fprintf(stderr, "remote address expected\n");
                return 2;
            }
            udpaddress_resolve(&address, *p++);
            tracker_callback(&config, &address, 0);
            continue;
        }
        if (strcmp(cmd, "--dev") == 0) {
            if (*p == 0) {
                fprintf(stderr, "Device name expected\n");

                return 2;
            }
            fprintf(stderr, "Creating device %s...\n", *p);
            config.master_fd = tun_create(*p++);
            if (config.master_fd < 0) {
                return 1;
            }
            config.master_event = event_new(config.event_base, config.master_fd, EV_READ | EV_PERSIST, (event_callback_fn)master_callback, &config);
            event_add(config.master_event, 0);
            continue;
        }
        if (strcmp(cmd, "--interface") == 0 || strcmp(cmd, "-i") == 0) {

            const char *name = *p++;
            struct interface *interface = malloc(sizeof(struct interface));

            if (name == 0) {
                fprintf(stderr, "interface name expected\n");
                return 2;
            }

            interface->priority = 1;
            interface->weight = 1;
            interface->name = strdup(name);
            interface->next = config.interfaces.next;
            interface->active = 0;
            config.interfaces.next = interface;
            continue;
        }
        fprintf(stderr, "Unknown option: %s\n", cmd);
        return 2;
    }

    /*open interfaces*/
    config.inotify = inotify_create(config.event_base, &config, (inotification_callback_t)inotify_callback);
    if (config.inotify == 0) {
        return 1;
    }


    {
        struct if_nameindex *ifp = if_nameindex();
        struct if_nameindex *p = ifp;
        struct ifaddrs *ifaddr;
        struct ifaddrs *ifa;

        if (getifaddrs(&ifaddr) == -1) {
            perror("getifaddrs");
            return 1;
        }

        while (p->if_index > 0 && p->if_name != 0) {
            struct inotification notification;

            notification.device = p->if_name;
            notification.type = INOTIFY_INT_ADDED;
            inotify_callback(&config, &notification);

            for (ifa = ifaddr; ifa != 0; ifa = ifa->ifa_next) {
               notification.address.family = ifa->ifa_addr->sa_family;
               if (strcmp(ifa->ifa_name, p->if_name) != 0) {
                   continue;
               }
               notification.type = INOTIFY_ADDR_ADDED;
               /* For an AF_INET* interface address, display the address */
               if (notification.address.family == AF_INET) {
                    notification.address.addr4 =  ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
               } else
               if (notification.address.family == AF_INET6) {
                    notification.address.addr6 =  ((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
               } else {
                    continue;
               }
               inotify_callback(&config, &notification);
           }

            p++;
        }
        if_freenameindex(ifp);

        freeifaddrs(ifaddr);

    }

    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    config.stdin_event = event_new(config.event_base, STDIN_FILENO, EV_READ | EV_PERSIST, (event_callback_fn)stdin_callback, &config);
    event_add(config.stdin_event, 0);

    event_base_dispatch(config.event_base);


    return 0;
}