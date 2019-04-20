#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include "ifl.h"
#include "iflfortls.h"
#include "iflfortls_common.h"
#include "ifl_t12client.h"

#define IFL_LOG_FILE "./ifl_log.txt"

FILE* g_ifl_log = NULL;

void ifl_log_cb(uint8_t log_level, const char *log_msg)
{
    fwrite(log_msg, strlen(log_msg), 1, g_ifl_log);
    fflush(g_ifl_log);
}

void ifl_log_init()
{
    IFL_SetLogCB(ifl_log_cb);
    g_ifl_log = fopen(IFL_LOG_FILE, "w");
    if (!g_ifl_log) {
        ERR("Log file open failed\n");
    }
}

void ifl_log_fini()
{
    fclose(g_ifl_log);
    g_ifl_log = NULL;
}

/* TODO: Need to get this client hello sample msg directly from OpenSSL */
char *g_client_hello="16030100bd010000b903035ff1ff2b1e6a610036e27ae59f9d9f9c18261ba739964718781360455c2c0426000038c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff01000058000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602";

int get_sample_msg(uint8_t **sample_msg, uint32_t *sample_msg_len)
{
    unsigned int val;
    int count = 0;
    int i;
    *sample_msg = (uint8_t *)calloc(1, strlen(g_client_hello) / 2);
    if (*sample_msg == NULL) {
        return -1;
    }
    for (i = 0; i < strlen(g_client_hello); i+=2) {
        sscanf(g_client_hello + i, "%02x", &val);
        *(*sample_msg + count) = (uint8_t)val;
        count++;
    }
    *sample_msg_len = strlen(g_client_hello) / 2;
    return 0;
}

void print_sample_msg(uint8_t *sample_msg, uint32_t sample_msg_len)
{
    int i;
    for (i = 0; i < sample_msg_len; i++) {
        printf("%02x ", sample_msg[i]);
    }
    printf("\n");
}

void wait_for_response(int fd)
{
    int ret;
    char buf[MAX_BUF_SIZE] = {0};
    if ((ret = recv(fd, buf, sizeof(buf) - 1, 0)) > 0) {
        DBG("Received resp of size %d\n", ret);
    } else {
        DBG("Recv failed with errno=%d\n", errno);
    }
}

int start_ifl()
{
    IFL *ifl = NULL;
    int ret_val = -1;
    int fd = -1;
    uint8_t *fuzzed_msg;
    uint32_t fuzzed_msg_len;
    uint8_t *sample_msg;
    uint32_t sample_msg_len;

    ifl_log_init();
    ifl = IFL_Init(IFL_CONF_CLIENT_HELLO_MSG, NULL);
    if (!ifl) {
        ERR("IFL init failed\n");
        goto err;
    }

    DBG("IFL created successfully\n");
    if (get_sample_msg(&sample_msg, &sample_msg_len)) {
        ERR("Getting sample msg failed\n");
        goto err;
    }

    print_sample_msg(sample_msg, sample_msg_len);

    if (IFL_Ctrl(ifl, IFL_CTRL_CMD_SET_SAMPLE_MSG, sample_msg, sample_msg_len)) {
        ERR("Setting sample msg failed\n");
        goto err;
    }

    do {
        if (IFL_GetFuzzedMsg(ifl, &fuzzed_msg, &fuzzed_msg_len)) {
            ERR("Get Fuzzed msg failed\n");
            goto err;
        }
        if (!fuzzed_msg) {
            DBG("Fuzzed msg generation finished\n");
            break;
        } else {
            LOG_BIN(fuzzed_msg, fuzzed_msg_len, "FuzzMsg");
            fd = do_tcp_connection(SERVER_IP, SERVER_PORT);
            if (fd == -1) {
                ERR("TCP connect failed\n");
                goto err;
            }
            if (send(fd, fuzzed_msg, (int)fuzzed_msg_len, 0) != fuzzed_msg_len) {
                ERR("TCP send on fd=%d failed\n", fd);
            }
            DBG("TCP send %d bytes data on fd=%d\n", fuzzed_msg_len, fd);
            IFL_FreeFuzzedMsg(fuzzed_msg);
            wait_for_response(fd);
        }
        CLOSE_FD(fd);
    } while(1);
    ret_val = 0;
err:
    IFL_Fini(ifl);
    ifl_log_fini();
    CLOSE_FD(fd);
    if (sample_msg) {
        free(sample_msg);
    }
    return ret_val;
}

int main()
{
    return start_ifl();
}
