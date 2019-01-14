#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "iflfortls.h"
#include "iflfortls_common.h"

int do_tcp_accept(const char *server_ip, uint16_t port)
{
    struct sockaddr_in addr;
    struct sockaddr_in peeraddr;
    socklen_t peerlen = sizeof(peeraddr);
    int lfd, cfd;
    int ret;

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        printf("Socket creation failed\n");
        return -1;
    }

    addr.sin_family = AF_INET;
    if (inet_aton(server_ip, &addr.sin_addr) == 0) {
        printf("inet_aton failed\n");
        goto err_handler;
    }
    addr.sin_port = htons(port);

    ret = bind(lfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret) {
        printf("bind failed\n");
        goto err_handler;
    }

    ret = listen(lfd, 5);
    if (ret) {
        printf("listen failed\n");
        goto err_handler;
    }

    printf("Listening on %s:%d\n", server_ip, port);
    printf("Waiting for TCP connection from client...\n");
    cfd = accept(lfd, (struct sockaddr *)&peeraddr, &peerlen);
    if (cfd < 0) {
        printf("accept failed, errno=%d\n", errno);
        goto err_handler;
    }

    printf("TCP connection accepted fd=%d\n", cfd);
    close(lfd);
    return cfd;
err_handler:
    close(lfd);
    return -1;
}

int do_tcp_connection(const char *server_ip, uint16_t port)
{
    struct sockaddr_in serv_addr;
    int fd;
    int ret;
    int retry = 0;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("Socket creation failed\n");
        return -1;
    }
    printf("Client fd=%d created\n", fd);

    serv_addr.sin_family = AF_INET;
    if (inet_aton(server_ip, &serv_addr.sin_addr) == 0) {
        printf("inet_aton failed\n");
        goto err_handler;
    }
    serv_addr.sin_port = htons(port);

    printf("TCP connecting to %s:%d\n", server_ip, port);
    do {
        ret = connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (!ret) break;
        retry++;
        usleep(TCP_RECONNECT_SLEEP_TIME_MS * 1000);
    } while(retry < TCP_CONNECT_MAX_RETRY);
    if (ret) {
        printf("Connect failed, ret=%d, errno=%d\n", ret, errno);
        goto err_handler;
    }

    printf("TCP connection succeeded, fd=%d\n", fd);
    return fd;
err_handler:
    close(fd);
    return -1;
}
