/*
*build command:
*   gcc -o cps cps.c -lpthread -lpcap
*/

#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h> 
#include <pthread.h>
#include <pcap/pcap.h>


#define VERSION "20190115"

#define LOGMSG(fmt, ...)    printf("\033[32mMSG: \033[0m"fmt, ##__VA_ARGS__)
#define LOGERR(fmt, ...)    printf("\033[31mERR: \033[0m"fmt, ##__VA_ARGS__)

typedef struct ether_header {
    unsigned char ether_dhost[6];
    unsigned char ether_shost[6];
    unsigned short ether_type;
}ETHHEADER,*PETHHEADER;

typedef struct ipv4_header {
    unsigned char ver_ihl;          //版本 (4 bits) + 首部长度 (4 bits)
    unsigned char tos;             //服务类型
    unsigned short tlen;            //数据报总长度
    unsigned short identification;    //标识
    unsigned short flags_fo;        //标志 (3 bits) + 片偏移 (13 bits)
    unsigned char ttl;             //生存时间
    unsigned char proto;           //协议
    unsigned short crc;            //首部校验和
    u_char ip_src[4];              //源IP地址
    u_char ip_dst[4];              //目的IP地址
}IPHEADER,*PIPHEADER;

typedef struct tcp_header {
    u_short SourPort;       //源端口号　　
    u_short DestPort;       //目的端口号
    u_int32_t SeqNo;       //序号
    u_int32_t AckNo;       //确认序号
    u_char HLen;          //首部长度（保留位）
    u_char Flag;           //标识（保留位）
    u_short Window;       //窗口大小
    u_short ChkSum;       //校验和
    u_short UrgPtr;        //紧急指针
}TCPHEADER,*PTCPHEADER;

typedef struct udp_header {
    u_short sport;          //源端口号
    u_short dport;          //目的端口号
    u_short len;            //数据报长度
    u_short crc;            //校验和
}UDPHEADER,*PUDPHEADER;

#define MUTEX
typedef struct _stat {
    unsigned long pre;
    unsigned long next;
    #ifdef MUTEX
    pthread_mutex_t calc_lock;
    #else
    pthread_spinlock_t calc_lock;
    #endif
} STAT;

STAT cps_stat;
unsigned char debug = 0;
unsigned char proto = 17; //default protocol is UDP
char *interface = NULL;
u_short port = 5060;
char *methods[] = {"INVITE", "REGISTER", "OPTIONS", "BYE"};
char *method_s = "INVITE";
u_char src_ip[4] = {0}; 
u_char dst_ip[4] = {0}; 

enum method_num {
    INVITE = 0,
    REGISTER,
    OPTIONS,
    BYT
};
unsigned char method = INVITE;

#ifdef MUTEX
#define LOCK_INIT(t)  pthread_mutex_init(t, NULL)
#define LOCK(t) pthread_mutex_lock(t)
#define UNLOCK(t) pthread_mutex_unlock(t)
#define LOCK_DESTROY(t) pthread_mutex_destroy(t)
#else
#define LOCK_INIT(t)  pthread_spin_init(t, PTHREAD_PROCESS_PRIVATE)
#define LOCK(t) pthread_spin_lock(t)
#define UNLOCK(t) pthread_spin_unlock(t)
#define LOCK_DESTROY(t) pthread_spin_destroy(t)
#endif

void print_usage()
{
    printf("Usage: cps <options> [param]\n");
    printf("-t: capture tcp\n");
    printf("-u: capture udp (default)\n");
    printf("-i [interface] :assign interface\n");
    printf("-p port :assign port(default 5060)\n");
    printf("-I: capture INVITE\n");
    printf("-R: capture REGISTER\n");
    printf("-s src ip :capture only from this ip\n");
    printf("-d dest ip :capture only from this ip\n");
    printf("-h: help\n");
}

int parse_ip(char *param, unsigned char src_ip[])
{
    if (param == NULL) {
        return -1; 
    }   

    char *seg;
    int cur, i = 0;
    seg = strtok(param, ".");
    while (seg) {
        cur = atoi(seg);
        if ((cur > 255) || (cur < 0)) {
            return -1; 
        }   
        src_ip[i++] = cur;
        seg = strtok(NULL, ".");
    }   

    return 0;
}

/*******************************************
*if a character is followed by a colon, 
*the option is expected to have an argument,
*which should be separated from it by white space.
********************************************/
int handle_opt(int argc, char *argv[])
{
    char oc;
    char *options = "v t u p:i:I R h H s:d:";

    while((oc = getopt(argc, argv, options)) != -1) {
        switch (oc) {
        case 'v':
            printf("version: [%s]\n", VERSION);
            exit(0);
            break;
            
        case 't':
            proto = 6;
            break;

        case 'u':
            proto = 17;
            break;

        case 'p':
            port = atoi(optarg);
            break;

        case 'i':
            interface = optarg;
            break;

        case 'I':
            method_s = methods[0];
            break;

        case 'R':
            method_s = methods[1];
            break;

        case 'h':
        case 'H':
            print_usage();
            return -1;

        case 's':
            if (parse_ip(optarg, src_ip)) {
                fprintf(stderr, "parase src ip error\n");
                return -1;
            }
            break;

        case 'd':
            if (parse_ip(optarg, dst_ip)) {
                fprintf(stderr, "parase dst ip error\n");
                return -1;
            }
            break;
        
        default:
            print_usage();
            return -1;
        }
    }

    return 0;
}

unsigned long max = 0;
void cps_timeout()
{
    unsigned long now_stat, cps;
    
    LOCK(&cps_stat.calc_lock);
    now_stat = cps_stat.next;
    UNLOCK(&cps_stat.calc_lock);

    if (now_stat < cps_stat.pre) {
        cps_stat.pre = 0;
        LOCK(&cps_stat.calc_lock);
        cps_stat.next = 0;
        UNLOCK(&cps_stat.calc_lock);  
    }

    cps = now_stat - cps_stat.pre;
    if (max < cps) {
        max = cps;
    }

    printf("%s: %20lu/s| max: %20lu/s| total: %20lu|\r", method_s, cps, max, now_stat);
    fflush(stdout);

    cps_stat.pre = now_stat;
}

#define EPOLL_MAXEVENTS 1
#define EPOLL_WAIT_TIME 1000

void *timer_thread()
{
    int epollfd, nevents = 0;
    struct epoll_event events[EPOLL_MAXEVENTS];
    struct epoll_event ev;
    int fd, flags;

    epollfd = epoll_create(EPOLL_MAXEVENTS);

    if((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        LOGERR("create socket failed\n");
        exit(-1);
    }
    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in server_addr;
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((uint32_t)12345);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(fd, (struct sockaddr*)&server_addr, sizeof(struct sockaddr)) == -1) {
        LOGERR("fail to bind\n");
        exit(-1);
    }

    if (listen(fd, 128) == -1) {
        LOGERR("fail to listen\n");
        exit(-1);
    }
    
    ev.events = EPOLLOUT;
    ev.data.fd = fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        LOGERR("add fd to epoll failed:%s\n", strerror(errno));
        exit(-1);
    }

    socklen_t sin_size = sizeof(struct sockaddr_in);
    struct sockaddr_in client_addr;
    int connfd = accept(fd, (struct sockaddr *)&client_addr, &sin_size);
    if(connfd == -1){
        if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
            LOGERR("fail to accept:%s\n", strerror(errno));
            exit(-1);
        }
    }

    while (1) {
        nevents = epoll_wait(epollfd, events, EPOLL_MAXEVENTS, EPOLL_WAIT_TIME);
        if (0 == nevents) {           
            cps_timeout();
            continue;
        }
    }

    close(fd);
}

void print_pkg(const u_char *pkg, bpf_u_int32 len)
{
    int i;
    
    for (i = 0; i < len; i++) {
        printf(" %02x", pkg[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }

    printf("\n\n");
}

/*
*struct pcap_pkthdr{	
*    struct timeval ts; // 抓到包的时间	
*    bpf_u_int32 caplen; // 表示抓到的数据长度	
*    bpf_u_int32 len; // 表示数据包的实际长度
*}
*/
void cps_main_loop(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    ETHHEADER *eth = (ETHHEADER *)packet;
    if ((eth->ether_dhost[0] == 0xFF) &&
        (eth->ether_dhost[1] == 0xFF) && 
        (eth->ether_dhost[2] == 0xFF) && 
        (eth->ether_dhost[3] == 0xFF) && 
        (eth->ether_dhost[4] == 0xFF) && 
        (eth->ether_dhost[5] == 0xFF)) {
        return;
    }
    
    if (eth->ether_type != 0x0008) {
        return;
    }

    IPHEADER *ip_hdr = (IPHEADER *)(packet + sizeof(ETHHEADER));
    if (src_ip[0] || src_ip[1] || src_ip[2] || src_ip[3]) {
        if (!(src_ip[0] == ip_hdr->ip_src[0] && 
            src_ip[1] == ip_hdr->ip_src[1] &&
            src_ip[2] == ip_hdr->ip_src[2] &&
            src_ip[3] == ip_hdr->ip_src[3])) {
            return;
        }
    }
    if (dst_ip[0] || dst_ip[1] || dst_ip[2] || dst_ip[3]) {
        if (!(dst_ip[0] == ip_hdr->ip_dst[0] && 
            dst_ip[1] == ip_hdr->ip_dst[1] &&
            dst_ip[2] == ip_hdr->ip_dst[2] &&
            dst_ip[3] == ip_hdr->ip_dst[3])) {
            return;
        }
    }
    
    if (ip_hdr->proto != proto) {
        return;
    }  

    u_short sport, dport;
    u_char *data = NULL;
    if (proto == 17) {
        UDPHEADER *udp_hdr = (UDPHEADER *)(packet + sizeof(ETHHEADER) + sizeof(IPHEADER));
        sport = ((udp_hdr->sport >> 8) & 0x00FF) + ((udp_hdr->sport << 8) & 0xFF00);
        dport = ((udp_hdr->dport >> 8) & 0x00FF) + ((udp_hdr->dport << 8) & 0xFF00);
        if (!(sport == port || dport == port)) {
            return;
        }

        data = (u_char *)udp_hdr + sizeof(UDPHEADER);
    } else if (proto == 6) {
        TCPHEADER *tcp_hdr = (TCPHEADER *)(packet + sizeof(ETHHEADER) + sizeof(IPHEADER));
        sport = ((tcp_hdr->SourPort >> 8) & 0x00FF) + ((tcp_hdr->SourPort << 8) & 0xFF00);
        dport = ((tcp_hdr->DestPort >> 8) & 0x00FF) + ((tcp_hdr->DestPort << 8) & 0xFF00);
        if (!(sport == port || dport == port)) {
            return;
        }

        data = (u_char *)tcp_hdr + sizeof(TCPHEADER);
    } else {
        return;
    }

    if (!strncmp(data, method_s, strlen(method_s))) {
        LOCK(&cps_stat.calc_lock);
        __sync_fetch_and_add(&cps_stat.next, 1);
        UNLOCK(&cps_stat.calc_lock);
    }

    if (debug) {
        printf("src: %d.%d.%d.%d\n", ip_hdr->ip_src[0], ip_hdr->ip_src[1], ip_hdr->ip_src[2], ip_hdr->ip_src[3]);
        printf("dst: %d.%d.%d.%d\n", ip_hdr->ip_dst[0], ip_hdr->ip_dst[1], ip_hdr->ip_dst[2], ip_hdr->ip_dst[3]);
        printf("proto: %d\n", ip_hdr->proto);
        printf("source port: %d\n", sport);
        printf("dest port: %d\n", dport);
        print_pkg(packet, pkthdr->len);
    }
        
}

int cps_init()
{
    char *dev;
    pcap_if_t *alldevsp;
    char err_msg[PCAP_ERRBUF_SIZE] = {0};
    int ret;

    if (interface) {
        dev = interface;
    } else {
        ret = pcap_findalldevs(&alldevsp, err_msg);
        if (-1 == ret) {
            LOGERR("get device fail: %s\n", err_msg);
            return -1;          
        } else {
            printf("get device ok: %s\n", dev);
            dev = alldevsp->name;
        }
    }
    
    pcap_t * device = pcap_open_live(dev, 65535, 0, 0, err_msg);
    if (!device) {
        LOGERR("open device failed: %s\n", err_msg);
        return -1;
    } else {
        printf("open device %s ok.\n", dev);
    }    

    printf("\n\n\n");
    printf("=========================================================================================\n");
   
    pcap_loop(device, -1, cps_main_loop, NULL);
    pcap_close(device);
    
}

int cps_start()
{
    pthread_t tid = 0;
    
    LOCK_INIT(&cps_stat.calc_lock);
    
    memset(&cps_stat, 0, sizeof(STAT));
    
    if (pthread_create(&tid, NULL, timer_thread, NULL)) {
        LOGERR("create timer thread failed!\n");
        return -1;
    }

    if (-1 == cps_init()) {
        LOGERR("cps init failed\n");
        return -1;
    }
    
    LOCK_DESTROY(&cps_stat.calc_lock);
    
    return 0;    
}

int main(int argc, char **argv)
{
    if (handle_opt(argc, argv)) {
        return -1;
    }

    if (-1 == cps_start()) {
        LOGERR("cps start failed\n");
        return -1;
    }
    
    return 0;
}

