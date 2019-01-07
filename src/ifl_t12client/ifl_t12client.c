#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "ifl.h"
#include "iflfortls.h"
#include "ifl_t12client.h"

#define IFL_LOG_FILE "./ifl_log.txt"

FILE* g_ifl_log = NULL;

int do_tcp_connection(const char *server_ip, uint16_t port)
{
    struct sockaddr_in serv_addr;
    int fd;
    int ret;

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

    ret = connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (ret) {
        printf("Connect failed, errno=%d\n", errno);
        goto err_handler;
    }

    printf("TLS connection succeeded, fd=%d\n", fd);
    return fd;
err_handler:
    close(fd);
    return -1;
}

void ifl_log_cb(uint8_t log_level, const char *log_msg)
{
    fwrite(log_msg, strlen(log_msg), 1, g_ifl_log);
}

void ifl_log_init()
{
    IFL_SetLogCB(ifl_log_cb);
    g_ifl_log = fopen(IFL_LOG_FILE, "w");
    if (!g_ifl_log) {
        printf("Log file open failed\n");
    }
}

void ifl_log_fini()
{
    fclose(g_ifl_log);
    g_ifl_log = NULL;
}

int start_ifl()
{
    IFL *ifl = NULL;
    int ret_val = -1;
    int fd;
    uint8_t *fuzzed_msg;
    uint32_t fuzzed_msg_len;

    ifl_log_init();
    ifl = IFL_Init(IFL_CONF_CLIENT_HELLO_MSG, NULL);
    if (!ifl) {
        printf("IFL init failed\n");
        goto err;
    }

    printf("IFL created successfully\n");

    do {
        fd = do_tcp_connection(SERVER_IP, SERVER_PORT);
        if (fd == -1) {
            printf("TCP connect failed\n");
            return -1;
        }
        printf("TCP Connection succeeded, fd=%d\n", fd);
        if (IFL_GetFuzzedMsg(ifl, &fuzzed_msg, &fuzzed_msg_len)) {
            printf("Get Fuzzed msg failed\n");
            goto err;
        }
        if (!fuzzed_msg) {
            printf("Fuzzed msg generation finished\n");
            break;
        } else {
            if (send(fd, fuzzed_msg, (int)fuzzed_msg_len, 0) != fuzzed_msg_len) {
                printf("TCP send on fd=%d failed\n", fd);
            }
            printf("TCP send len=%d on fd=%d\n", fuzzed_msg_len, fd);
            IFL_FreeFuzzedMsg(fuzzed_msg);
        }
    } while(1);
    ret_val = 0;
err:
    IFL_Fini(ifl);
    ifl_log_fini();
    return ret_val;
}

int main()
{
    return start_ifl();
}
