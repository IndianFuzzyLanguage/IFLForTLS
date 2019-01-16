#include <stdio.h>

#include "iflfortls.h"
#include "iflfortls_common.h"
#include "iflfortls_log.h"

void log_bin(uint8_t *buf, uint16_t buf_size, const char *type)
{
    int i;
    printf("%s[%d]:", type, buf_size);
    for (i = 0; i < buf_size; i++) printf(" %x", buf[i]);
    printf("\n");
}

