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
#include "iflfortls_log.h"

int do_tcp_listen(const char *server_ip, uint16_t port)
{
    struct sockaddr_in addr;
    int lfd;
    int ret;

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        ERR("Socket creation failed\n");
        return -1;
    }

    addr.sin_family = AF_INET;
    if (inet_aton(server_ip, &addr.sin_addr) == 0) {
        ERR("inet_aton failed\n");
        goto err_handler;
    }
    addr.sin_port = htons(port);

    ret = bind(lfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret) {
        ERR("bind failed\n");
        goto err_handler;
    }

    ret = listen(lfd, 5);
    if (ret) {
        ERR("listen failed\n");
        goto err_handler;
    }
    DBG("Listening on %s:%d\n", server_ip, port);
    DBG("TCP listen fd=%d\n", lfd);
    return lfd;
err_handler:
    close(lfd);
    return -1;
}

int do_tcp_accept(int lfd)
{
    struct sockaddr_in peeraddr;
    socklen_t peerlen = sizeof(peeraddr);
    int cfd;

    DBG("Waiting for TCP connection from client...\n");
    cfd = accept(lfd, (struct sockaddr *)&peeraddr, &peerlen);
    if (cfd < 0) {
        ERR("accept failed, errno=%d\n", errno);
        return -1;
    }

    DBG("TCP connection accepted fd=%d\n", cfd);
    return cfd;
}

int do_tcp_connection(const char *server_ip, uint16_t port)
{
    struct sockaddr_in serv_addr;
    int fd;
    int ret;
    int retry = 0;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        ERR("Socket creation failed\n");
        return -1;
    }
    DBG("Client fd=%d created\n", fd);

    serv_addr.sin_family = AF_INET;
    if (inet_aton(server_ip, &serv_addr.sin_addr) == 0) {
        ERR("inet_aton failed\n");
        goto err_handler;
    }
    serv_addr.sin_port = htons(port);

    DBG("TCP connecting to %s:%d\n", server_ip, port);
    do {
        ret = connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (!ret) break;
        retry++;
        usleep(TCP_RECONNECT_SLEEP_TIME_MS * 1000);
    } while(retry < TCP_CONNECT_MAX_RETRY);
    if (ret) {
        ERR("Connect failed, ret=%d, errno=%d\n", ret, errno);
        goto err_handler;
    }

    DBG("TCP connection succeeded, fd=%d\n", fd);
    return fd;
err_handler:
    close(fd);
    return -1;
}
