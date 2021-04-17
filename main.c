#include "MADns.h"
#include <pthread.h>

int num=1;
void my_callback(MADNS_PACKAGE *pkgs, size_t pkg_cnt)
{
    // for (size_t i = 0; i < pkg_cnt; i++)
    // {
    //     printf("%s\r\n", pkgs[i].data);
    // }
    printf("%d\r\n",num);
    num++;
}

int main(void)
{
    MADNS_CLIENT *client = dns_client_init(my_callback);

    pthread_t id;
    pthread_create(&id,NULL,dns_client_run,client);

    for (size_t i = 0; i < 100; i++)
    {
        dns_req(client, "114.114.114.114", 53, "www.baidu.com");
    }
    dns_client_shudown(client);

    getchar();
}
