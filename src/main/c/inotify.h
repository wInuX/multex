#ifndef _M_INOTIFY_H_
#define _M_INOTIFY_H_

#define INOTIFY_INT_ADDED 1
#define INOTIFY_INT_REMOVED 2
#define INOTIFY_ADDR_ADDED 3
#define INOTIFY_ADDR_REMOVED 4

#include <event2/event.h>
#include "io.h"

struct inotify;

struct inotification {
    int type;
    char* device;
    struct ipaddress address;
};

typedef void (*inotification_callback_t)(void* context, struct inotification* notification);


struct inotify* inotify_create(struct event_base* base, void* context, inotification_callback_t callback);

void inotify_close(struct inotify* notify);

#endif