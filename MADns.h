#ifndef MADNS_H
#define MADNS_H

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

#define EPOLL_SIZE 2048

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
    uint16_t data_class;
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
    char shutdown;
    int32_t epfd;
    void (*callback)(MADNS_PACKAGE *pkgs, size_t pkgs_cnt);
    struct epoll_event *ep_event;
    //1为存在,0为close()
    char sock_live[EPOLL_SIZE];
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

//解析dns
static MADNS_PACKAGE *dns_resp_parse(MADNS_RESPONSE *resp);

static void dns_free_client(MADNS_CLIENT* client);
//设置非阻塞套接字
static void dns_set_nonblock(int fd);
//接受数据处理
static void dns_epoll_deal(int fd, MADNS_CLIENT *client);

static void dns_free_pkg(MADNS_PACKAGE *pkg, size_t cnt);

static void dns_free_resp(MADNS_RESPONSE *resp);


//格式化域名
char *dns_domain_fmt(const char *domain);
//反格式化域名
char *dns_fmt_domain(const char *fmt_domain, size_t len);
//ip 转 string
char *dns_net_ip(uint32_t ip);
//发起dns请求
void dns_req(MADNS_CLIENT *client, char* server_ip,uint16_t port,const char *domain);
//epoll循环
void dns_client_run(MADNS_CLIENT *client);
//初始化client
MADNS_CLIENT *dns_client_init(void (*callback)(MADNS_PACKAGE *pkgs, size_t pkgs_cnt));

void dns_client_shudown(MADNS_CLIENT* client);


#endif
