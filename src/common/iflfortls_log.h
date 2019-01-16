#ifndef _IFLFORTLS_LOG_H_
#define _IFLFORTLS_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define LOG_FUNC(fmt, ...) printf(fmt, ##__VA_ARGS__);

#define ERR(fmt, ...) LOG_FUNC("[ERR]"fmt, ##__VA_ARGS__);
#define INFO(fmt, ...) LOG_FUNC("[INFO]"fmt, ##__VA_ARGS__);
#define DBG(fmt, ...) LOG_FUNC("[DBG]"fmt, ##__VA_ARGS__);

void log_bin(uint8_t *buf, uint16_t buf_size, const char *type);

#define LOG_BIN(buf, buf_size, type) log_bin(buf, buf_size, type)

#ifdef __cplusplus
}
#endif

#endif
