#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "ifl.h"
#include "iflfortls.h"
#include "iflfortls_common.h"
#include "ifl_t12client.h"

#define IFL_LOG_FILE "./ifl_log.txt"

FILE* g_ifl_log = NULL;

void print_bin(uint8_t *buf, uint16_t buf_size, const char *type)
{
    int i;
    printf("%s[%d]:", type, buf_size);
    for (i = 0; i < buf_size; i++) printf(" %x", buf[i]);
    printf("\n");
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
    int fd = -1;
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
        if (IFL_GetFuzzedMsg(ifl, &fuzzed_msg, &fuzzed_msg_len)) {
            printf("Get Fuzzed msg failed\n");
            goto err;
        }
        if (!fuzzed_msg) {
            printf("Fuzzed msg generation finished\n");
            break;
        } else {
            print_bin(fuzzed_msg, fuzzed_msg_len, "FuzzMsg");
            if (send(fd, fuzzed_msg, (int)fuzzed_msg_len, 0) != fuzzed_msg_len) {
                printf("TCP send on fd=%d failed\n", fd);
            }
            printf("TCP send %d bytes data on fd=%d\n", fuzzed_msg_len, fd);
            IFL_FreeFuzzedMsg(fuzzed_msg);
        }
        CLOSE_FD(fd);
    } while(1);
    ret_val = 0;
err:
    IFL_Fini(ifl);
    ifl_log_fini();
    CLOSE_FD(fd);
    return ret_val;
}

int main()
{
    return start_ifl();
}