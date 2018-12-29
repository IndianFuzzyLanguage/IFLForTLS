#include "ifl.h"
#include "ifl_tls12_client.h"

int main()
{
    IFL *ifl;

    ifl = IFL_init(IFL_CONF_CLIENT_HELLO_MSG, NULL);
    if (!ifl) {
        printf("IFL init failed\n");
        goto err;
    }

    printf("IFL created successfully\n");

    IFL_fini(ifl);
    return 0;
err:
    return -1;
}
