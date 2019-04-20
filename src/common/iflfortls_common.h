#ifndef _IFLFORTLS_COMMON_H_
#define _IFLFORTLS_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>

#include "iflfortls_log.h"

#define MAX_BUF_SIZE 1024

#define CLOSE_FD(fd) \
    do { \
        if (fd > -1) { \
            DBG("Closing fd=%d\n", fd); \
            close(fd); \
            fd = -1; \
        } \
    } while(0)

int do_tcp_listen(const char *server_ip, uint16_t port);

int do_tcp_accept(int lfd);

int do_tcp_connection(const char *server_ip, uint16_t port);

#ifdef __cplusplus
}
#endif

#endif
