#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ifl.h"
#include "ifl_t12client.h"

#define IFL_LOG_FILE "./ifl_log.txt"

FILE* g_ifl_log = NULL;

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

int main()
{
    IFL *ifl = NULL;
    int ret_val = -1;

    ifl_log_init();
    ifl = IFL_Init(IFL_CONF_CLIENT_HELLO_MSG, NULL);
    if (!ifl) {
        printf("IFL init failed\n");
        goto err;
    }

    printf("IFL created successfully\n");

    ret_val = 0;
err:
    IFL_Fini(ifl);
    ifl_log_fini();
    return ret_val;
}
