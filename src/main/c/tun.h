#ifndef _M_TUN_H_
#define _M_TUN_H_

int tun_create(const char *dev);

ssize_t tun_read(int fd, char* buf, size_t count);

ssize_t tun_write(int fd, char* buf, size_t count);

void tun_close();

#endif