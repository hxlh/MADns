#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define EPOLL_SIZE 1024

///< DNS首部标志
typedef struct _MADNS_HEADER_FLAG
{
    uint8_t uQR : 1;      ///< 报文类型, 0:查询报文, 1:响应报文
    uint8_t uOpCode : 4;  ///< 查询或响应类型, 0:标准的, 1:反响的, 2:服务器状态请求
    uint8_t uAA : 1;      ///< 值为1表示服务器是权限服务器
    uint8_t uTC : 1;      ///< 值为1时,表示响应已超过512字节并已截断为512字节
    uint8_t uRD : 1;      ///< 值为1时,表示客户希望得到递归回答;在查询报文中置位,在响应报文中重复置位
    uint8_t uRA : 1;      ///< 值为1时,表示可得到递归响应;只能在响应报文中置位
    uint8_t uReserve : 3; ///< 保留位,目前全置0
    uint8_t uRCode : 4;   ///< 表示响应中的差错状态
} MADNS_HEADER_FLAG;

///< DNS协议首部
typedef struct _MADNS_HEADER
{
    uint16_t uTicket;            ///< 用户关联客户端查询和服务端响应的标识
    MADNS_HEADER_FLAG flag;      ///< 标志
    uint16_t uQuestionRecordNum; ///< 问题记录数
    uint16_t uResRecordNum;      ///< 回答记录数,在查询报文中为0
    uint16_t uWarrantNum;        ///< 授权记录数,在查询报文中为0
    uint16_t uAdditionNum;       ///< 附加记录数,在查询报文中为0
} MADNS_HEADER;

///< 问题记录
typedef struct _MADNS_QUESTION_RECORD
{
    char *strDomain;    ///< 格式化后的域名
    uint16_t uType;     ///< 查询类型
    uint16_t uCategory; ///< 查询类别
} MADNS_QUESTION_RECORD;

//DNS 解析后的pkg
typedef struct _MADNS_PACKAGE
{
    uint16_t type;
    uint16_t class;
    uint32_t time_to_live;
    char *data;
} MADNS_PACKAGE;

//DNS response
typedef struct _MADNS_RESPONSE
{
    //回答记录数
    uint16_t aws_n;
    //data len;
    size_t data_len;
    //未解析的原始数据
    uint8_t *data;
} MADNS_RESPONSE;

typedef struct _MADNS_CLIENT
{
    int32_t epfd;
    struct sockaddr_in server;
    struct epoll_event *ep_event;
    void (*callback)(MADNS_PACKAGE *pkgs, size_t pkgs_cnt);
} MADNS_CLIENT;

///< DNS查询类型
enum enumDNS_QUERY_TYPE
{
    enumDNS_QTYPE_A = 1,      ///< 32位的IPv6地址
    enumDNS_QTYPE_NS = 2,     ///< 名字服务器
    enumDNS_QTYPE_CNAME = 5,  ///< 规范名称
    enumDNS_QTYPE_SOA = 6,    ///< 授权开始
    enumDNS_QTYPE_WKS = 11,   ///< 熟知服务
    enumDNS_QTYPE_PTR = 12,   ///< 指针
    enumDNS_QTYPE_HINFO = 13, ///< 主机信息
    enumDNS_QTYPE_MX = 15,    ///< 邮件交换
    enumDNS_QTYPE_AAAA = 28,  ///< IPv6地址
    enumDNS_QTYPE_AXFR = 252, ///< 请求传送完整区文件
    enumDNS_QTYPE_ANY = 255   ///< 请求所有记录
};

///< DNS查询类别
enum enumDNS_QUERY_CATEGORY
{
    enumDNS_QCATEGORY_AN = 1,    ///< 因为特
    enumDNS_QCATEGORY_CSNET = 2, ///< CSNET网络
    enumDNS_QCATEGORY_CS = 3,    ///< COAS网络
    enumDNS_QCATEGORY_HS = 4     ///< 由MIT开发的Hesoid服务器
};

//格式化域名
char *dns_domain_fmt(const char *domain)
{
    char *res = NULL;
    size_t resl = 0;
    const char *p = domain;
    for (;;)
    {
        const char *temp = strchr(p, '.');
        if (temp == NULL)
        {
            size_t len = strlen(p);
            char *tmpStr = (char *)malloc(resl + len + 1);
            memcpy(tmpStr, res, resl);
            free(res);
            res = NULL;

            tmpStr[resl] = len;

            memcpy(tmpStr + resl + 1, p, len);

            res = tmpStr;
            res[resl + len + 1] = '\0';
            break;
        }
        size_t len = strlen(p) - strlen(temp);

        char *tmpStr = (char *)malloc(resl + len + 1);
        if (res != NULL)
        {
            memcpy(tmpStr, res, resl);
            free(res);
            res = NULL;
        }
        tmpStr[resl] = len;
        memcpy(tmpStr + resl + 1, p, len);

        res = tmpStr;

        resl += len + 1;

        p = temp;
        p++;
    }
    return res;
};

//反格式化域名
char *dns_fmt_domain(const char *fmt_domain, size_t len)
{
    char t = 0;

    size_t sLen = 0;
    //计算长度
    for (size_t i = 0; i < len; i++)
    {
        if ((fmt_domain[i] >= 'a' && fmt_domain[i] <= 'z') || fmt_domain[i] == '-' || (fmt_domain[i] >= '0' && fmt_domain[i] <= '9'))
        {
            sLen++;
        }
    }

    size_t rindex = 0;

    //符号个数
    size_t other = len - sLen;
    size_t dot = other - 2;

    char *res = (char *)malloc(sLen + dot);

    for (size_t i = 0; i < len; i++)
    {

        if ((fmt_domain[i] >= 'a' && fmt_domain[i] <= 'z') || fmt_domain[i] == '-' || (fmt_domain[i] >= '0' && fmt_domain[i] <= '9'))
        {
            size_t pos = i + 1;
            for (;;)
            {

                if ((fmt_domain[pos] >= 'a' && fmt_domain[pos] <= 'z') || fmt_domain[pos] == '-' || (fmt_domain[pos] >= '0' && fmt_domain[pos] <= '9'))
                {
                    pos++;
                }
                else
                {
                    break;
                }
            }

            memcpy(&res[rindex], &fmt_domain[i], pos - i);
            if (dot > 0)
            {
                res[rindex + (pos - i)] = '.';
                dot--;
                rindex += (pos - i) + 1;
            }
            else
            {
                rindex += (pos - i);
            }
            i = pos - 1;
        }
        else
        {
            other--;
        }
        if (other <= 0)
        {
            break;
        }
    }
    return res;
}

//int to ip string
char *dns_net_ip(uint32_t ip)
{
    uint8_t a = (ip & 0xff000000) >> 24;

    uint8_t b = (ip & 0x00ff0000) >> 16;

    uint8_t c = (ip & 0x0000ff00) >> 8;

    uint8_t d = (ip & 0x000000ff);

    char *tmp = (char *)malloc(15);
    sprintf(tmp, "%d.%d.%d.%d", a, b, c, d);
    return tmp;
}

//解析response
MADNS_PACKAGE *dns_resp_parse(MADNS_RESPONSE *resp)
{
    //解析
    //查询与回复之间有生存时间为4个字节
    /*
    每个answer的内存布局
    -----------------15  16------------------31
    c0(1) 0c(未知)(1) type(2) class(2) 
    -----------------------------------------
                time to live(4)
    -----------------------------------------
    data Len(2)   | data
                    aata
    -----------------------------------------
    */

    MADNS_PACKAGE *pkgs = (MADNS_PACKAGE *)malloc(sizeof(MADNS_PACKAGE) * resp->aws_n);
    size_t pkg_pos = 0;

    for (size_t i = 0; i < resp->data_len; i++)
    {
        if (resp->data[i] == 0xc0)
        {
            //解析数据包
            //Type(2)
            uint16_t data_type = 0;
            memcpy(&data_type, &resp->data[i + 2], sizeof(uint16_t));
            data_type = ntohs(data_type);
            //Class(2)
            uint16_t data_class = 0;
            memcpy(&data_class, &resp->data[i + 4], sizeof(uint16_t));
            data_class = ntohs(data_class);
            //Time to live(4)
            uint32_t time_live = 0;
            memcpy(&time_live, &resp->data[i + 6], sizeof(uint32_t));
            time_live = ntohl(time_live);
            //data len;
            uint16_t data_len;
            memcpy(&data_len, &resp->data[i + 10], sizeof(uint16_t));
            data_len = ntohs(data_len);
            //data
            // char *data = (char *)malloc(data_len);
            // memcpy(data, &buf[i + 12], data_len);
            switch (data_type)
            {
            case enumDNS_QTYPE_A:
            {
                int ip = 0;
                memcpy(&ip, &resp->data[i + 12], data_len);
                ip = ntohl(ip);
                pkgs[pkg_pos].class = data_class;
                pkgs[pkg_pos].type = data_type;
                pkgs[pkg_pos].time_to_live = time_live;
                pkgs[pkg_pos].data = dns_net_ip(ip);
                break;
            }

            case enumDNS_QTYPE_CNAME:
                pkgs[pkg_pos].class = data_class;
                pkgs[pkg_pos].type = data_type;
                pkgs[pkg_pos].time_to_live = time_live;
                char *data = (char *)malloc(data_len);

                memcpy(data, &resp->data[i + 12], data_len);

                pkgs[pkg_pos].data = dns_fmt_domain(data, data_len);

                break;
            }

            //-1是因为后面要i++
            i = i + 12 + data_len - 1;
            pkg_pos++;
        }
    }
    return pkgs;
}

void dns_free_pkg(MADNS_PACKAGE *pkg, size_t cnt)
{
    for (size_t i = 0; i < cnt; i++)
    {
        free(pkg[i].data);
        pkg[i].data = NULL;
    }
    free(pkg);
}

void dns_free_resp(MADNS_RESPONSE *resp)
{
    free(resp->data);
    resp->data = NULL;
    free(resp);
    resp == NULL;
}

void dns_set_nonblock(int fd)
{
    int flag = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flag | O_NONBLOCK);
}

//发送dns请求
void dns_req(MADNS_CLIENT *client, const char *domain)
{
    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    

    struct epoll_event event;
    event.data.fd = fd;
    event.events = EPOLLIN | EPOLLET;
    epoll_ctl(client->epfd, EPOLL_CTL_ADD, fd, &event);
    dns_set_nonblock(fd);

    MADNS_HEADER dnsH;
    dnsH.uTicket = htons(1);
    *(uint16_t *)&dnsH.flag = htons(0x0100);
    dnsH.uQuestionRecordNum = htons(1);
    dnsH.uAdditionNum = htons(0);
    dnsH.uWarrantNum = htons(0);
    dnsH.uResRecordNum = htons(0);

    MADNS_QUESTION_RECORD dnsR;

    size_t size = sizeof(dnsR);

    char *domainFmt = dns_domain_fmt(domain);

    dnsR.strDomain = domainFmt;

    dnsR.uType = htons(enumDNS_QTYPE_A);
    dnsR.uCategory = htons(enumDNS_QCATEGORY_AN);

    unsigned char sedBuf[512];

    memset(sedBuf, 0, sizeof(sedBuf));

    memcpy(&sedBuf, &dnsH, sizeof(dnsH));

    memcpy(&sedBuf[12], domainFmt, strlen(domainFmt));
    size_t data_len = strlen(domainFmt) + 12;

    sedBuf[data_len] = 0;
    data_len++;

    memcpy(&sedBuf[data_len], &dnsR.uType, sizeof(dnsR.uType) * 2);
    data_len += sizeof(dnsR.uType) * 2;

    sendto(fd, sedBuf, data_len, 0, (const struct sockaddr *)&client->server, sizeof(struct sockaddr_in));

    
}

void my_callback(MADNS_PACKAGE *pkgs, size_t pkg_cnt)
{
    for (size_t i = 0; i < pkg_cnt; i++)
    {
        printf("%s\r\n", pkgs[i].data);
    }
}

void dns_epoll_deal(int fd, MADNS_CLIENT *client, struct sockaddr_in server)
{
    size_t buf_len = 2048;
    uint8_t *buf = (uint8_t *)malloc(buf_len);

    size_t data_len = 0;
    struct sockaddr_in ser;
    socklen_t addr_len = 0;
    for (;;)
    {
        ssize_t free_size = buf_len - data_len;
        ssize_t recved = recvfrom(fd, &buf[data_len], free_size, 0,NULL,NULL);
        data_len += recved;

        if (recved == 0)
        {
            //close
            epoll_ctl(client->epfd, EPOLL_CTL_DEL, fd, NULL);
            close(fd);
            break;
        }else if (recved < 0)
        {
            if (errno == EAGAIN)
            {
                //数据已读完
                uint16_t asw_n = 0;
                asw_n = ntohs(((MADNS_HEADER *)buf)->uResRecordNum);
                for (size_t i = 0; i < data_len; i++)
                {
                    if (buf[i] == 0xc0)
                    {
                        MADNS_RESPONSE *resp = (MADNS_RESPONSE *)malloc(sizeof(MADNS_RESPONSE));
                        resp->data = (uint8_t *)malloc(data_len - i);
                        resp->aws_n = asw_n;
                        resp->data_len = data_len - i;
                        memcpy(resp->data, &buf[i], data_len - i);
                        free(buf);
                        buf = NULL;

                        MADNS_PACKAGE *pkgs = dns_resp_parse(resp);
                        client->callback(pkgs, resp->aws_n);

                        dns_free_pkg(pkgs, resp->aws_n);
                        
                        dns_free_resp(resp);
                        
                        break;
                    }
                }

                break;
            }
        }
        else
        {
            if (data_len >= buf_len)
            {
                //扩容
                uint8_t *tmp = (uint8_t *)malloc(buf_len * 1.5);
                memcpy(tmp, buf, buf_len);
                free(buf);
                buf = tmp;
                buf_len = buf_len * 1.5;
            }
        }
    }
}

void dns_client_run(MADNS_CLIENT *client)
{
    for (;;)
    {
        size_t event_cnt = epoll_wait(client->epfd, client->ep_event, EPOLL_SIZE, -1);
        if (event_cnt == -1)
        {
            puts("epoll_wait() error");
        }
        for (size_t i = 0; i < event_cnt; i++)
        {
            dns_epoll_deal(client->ep_event[i].data.fd, client, client->server);
        }
    }
}

MADNS_CLIENT *dns_client_init(struct sockaddr_in server, void (*callback)(MADNS_PACKAGE *pkgs, size_t pkgs_cnt))
{
    MADNS_CLIENT *client = (MADNS_CLIENT *)malloc(sizeof(MADNS_CLIENT));
    client->callback = callback;
    client->server = server;
    client->epfd = epoll_create(EPOLL_SIZE);
    client->ep_event = (struct epoll_event *)malloc(sizeof(struct epoll_event) * EPOLL_SIZE);
    return client;
}

int main(void)
{
    struct sockaddr_in addr;
    addr.sin_port = htons(53);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("114.114.114.114");

    MADNS_CLIENT *client = dns_client_init(addr, my_callback);
    dns_req(client, "www.qq.com");
    dns_req(client, "www.baidu.com");
    dns_req(client, "www.csdn.com");
    dns_req(client, "www.moulem.com");
    dns_req(client, "www.youtube.com");
    dns_client_run(client);
    // for(int i=0;i<resp->aws_n;i++)
    // {
    //     printf("%s\r\n",tmp[i].data);
    //     MADNS_PACKAGE* p=&tmp[i];
    //     dns_free_pkg(p);
    // }
    getchar();
}
