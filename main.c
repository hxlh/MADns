#include "MADns.h"
#include <pthread.h>
#include <unistd.h>

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
        dns_req(client, "223.6.6.6", 53, "www.qq.com");
        printf("sended: %d\r\n",i);
        usleep(100000);
    }
    for (size_t i = 100; i < 200; i++)
    {
        dns_req(client, "114.114.114.114", 53, "www.qq.com");
        printf("sended: %d\r\n",i);
        usleep(100000);
    }
    sleep(30);
    dns_client_shudown(client);

    getchar();
}
