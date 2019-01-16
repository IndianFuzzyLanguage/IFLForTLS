#ifndef _IFLFORTLS_LOG_H_
#define _IFLFORTLS_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

#define LOG_FUNC(fmt, ...) printf(fmt, ##__VA_ARGS__);

#define ERR(fmt, ...) LOG_FUNC("[ERR]"fmt, ##__VA_ARGS__);
#define INFO(fmt, ...) LOG_FUNC("[INFO]"fmt, ##__VA_ARGS__);
#define DBG(fmt, ...) LOG_FUNC("[DBG]"fmt, ##__VA_ARGS__);

#ifdef __cplusplus
}
#endif

#endif
