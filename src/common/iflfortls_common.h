#ifndef _IFLFORTLS_COMMON_H_
#define _IFLFORTLS_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>

#define CLOSE_FD(fd) \
    do { \
        if (fd > -1) { \
            printf("Closing fd=%d\n", fd); \
            close(fd); \
            fd = -1; \
        } \
    } while(0)

int do_tcp_accept(const char *server_ip, uint16_t port);

int do_tcp_connection(const char *server_ip, uint16_t port);

#ifdef __cplusplus
}
#endif

#endif
