#ifndef _M_TRACKER_H_
#define _M_TRACKER_H_

#include "io.h"

struct tracker;

typedef void (*tracker_callback_t)(void* context, struct udpaddress* peer, unsigned long long timeout);

struct tracker* tracker_create(struct event_base* event_base, void* context, tracker_callback_t callback);

void tracker_add(struct tracker* tracker, const char* host);

void tracker_add_endpoint(struct tracker* tracker, struct ipaddress* local);

void tracker_remove_endpoint(struct tracker* tracker, struct ipaddress* local);

void tracker_close(struct tracker* tracker);

#endif