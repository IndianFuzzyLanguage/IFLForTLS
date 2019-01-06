#ifndef _IFLFORTLS_CONF_H_
#define _IFLFORTLS_CONF_H_

#ifdef __cplusplus
extern "C" {
#endif

#define CAFILE1 "./certs/ECC_Prime256_Certs/rootcert.pem"
#define SERVER_CERT_FILE "./certs/ECC_Prime256_Certs/serv_cert.pem"
#define SERVER_KEY_FILE "./certs/ECC_Prime256_Certs/serv_key.der"
#define EC_CURVE_NAME NID_X9_62_prime256v1

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 7788

#ifdef __cplusplus
}
#endif

#endif
