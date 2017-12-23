#ifndef NECESSARY_H
#define NECESSARY_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <netdb.h>
#include <cstdlib>
#include <iostream>
#include <QString>
#include <QStandardItemModel>
#include <QObject>
#include <QList>
#include <cstring>
#include <string>
#include "log.h"

//ThreadState
#define START 1
#define PAUSE 2
#define STOP 0

// MacHeader（14 Byte）
typedef struct _eth_header{
    unsigned char dstmac[6];	// 目标mac地址
    unsigned char srcmac[6];	// 来源mac地址
    unsigned short eth_type;	// 以太网类型
}eth_header;

//以太网帧类型　　　　　　　　　对应编码
#define EPT_IP             (0x0008)
#define EPT_IPv6           (0xDD86)
#define EPT_ARP            (0x0608)

// ARP Header（28 Byte）
typedef struct _arp_header{
    unsigned short arp_hdw;		// 硬件类型
    unsigned short arp_pr;		// 协议类型
    unsigned char arp_hl;		// 硬件地址长度
    unsigned char arp_pl;		// 协议地址长度
    unsigned short arp_opt;		// ARP操作类型
    unsigned char arp_sha[6];	// 发送者的硬件地址,不管了，eth_header中已经处理
    unsigned char arp_spa[4];		// 发送者的协议地址
    unsigned char arp_tha[6];	// 目标的硬件地址，不管了，eth_header中已经处理
    unsigned char arp_tpa[4];		// 目标的协议地址
}arp_header;

// IP 协议头 协议(Protocol) 字段标识含义
//      协议      协议号

#define IP_SIG			(0)
#define ICMP_SIG		(1)
#define IGMP_SIG		(2)
#define GGP_SIG			(3)
#define IP_ENCAP_SIG	(4)
#define ST_SIG			(5)
#define TCP_SIG			(6)
#define EGP_SIG			(8)
#define PUP_SIG			(12)
#define UDP_SIG			(17)
#define HMP_SIG			(20)
#define XNS_IDP_SIG		(22)
#define RDP_SIG			(27)
#define TP4_SIG			(29)
#define XTP_SIG			(36)
#define DDP_SIG			(37)
#define IDPR_CMTP_SIG	(39)
#define RSPF_SIG		(73)
#define VMTP_SIG		(81)
#define OSPFIGP_SIG		(89)
#define IPIP_SIG		(94)
#define ENCAP_SIG		(98)

// IPv4Header（20 Byte）
typedef struct _ip_header{
    unsigned char		ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    unsigned char		tos;            // 服务类型(Type of service)
    unsigned short		tlen;           // 总长(Total length)
    unsigned short		identification; // 标识(Identification)
    unsigned short		flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    unsigned char		ttl;            // 存活时间(Time to live)
    unsigned char		proto;          // 协议(Protocol)
    unsigned short		crc;			// 首部校验和(Header checksum)
    unsigned char		saddr[4];		// 源地址(Source address)
    unsigned char		daddr[4];		// 目标地址(Destination address)
    unsigned char       *optionData;
    unsigned short      optionLen;
    unsigned short      hl;
}ip_header;

// IPv6Header（40 Byte）
typedef struct _ipv6_header{
    unsigned short		ver_TC_FL;      // version(4 bits) + Traffic Class(8 bits) + Flow Label(First 4 bits)
    unsigned short		FLa;            // Flow Label(Last 16 bits)
    unsigned short		pld;            // Playload(8 bits)
    unsigned char       nhd;            // Next Header(4 bits)
    unsigned char		hlmt;           // Hop Limit(4 bits)
    unsigned char		saddr[16];		// 源地址(16 byte)
    unsigned char		daddr[16];		// 目标地址(16 byte)
}ipv6_header;

// TCPHeader（20 Byte）
typedef struct _tcp_header{
    unsigned short      sport;				// 源端口号
    unsigned short      dport;				// 目的端口号
    unsigned int        seq_no;				// 序列号
    unsigned int        ack_no;				// 确认号
    unsigned char       thl;				// tcpHeader长度
    unsigned char       flag;				// 12位标志
    unsigned short      wnd_size;			// 16位窗口大小
    unsigned short      chk_sum;			// 16位TCP检验和
    unsigned short      urgt_p;				// 16为紧急指针
    unsigned char       *optionData;
    unsigned short      optionLen;
    unsigned short      hl;
}tcp_header;

// UDPHeader（8 Byte）
typedef struct _udp_header{
    unsigned short      sport;		// 源端口(Source port)
    unsigned short      dport;		// 目的端口(Destination port)
    unsigned short      len;		// UDP数据包长度(Datagram length)
    unsigned short      crc;		// 校验和(Checksum)
}udp_header;

//icmpHeader
typedef struct _icmp_header{
    unsigned char       type;
    unsigned char       code;
    unsigned short      crc;

}icmp_header;

//igmp
typedef struct _igmp_header{
    unsigned char  type;
    unsigned char  maxRespCode;
    unsigned short crc;
    unsigned char   groupAddress[4];//ip
    unsigned short resvSQrvQQIC;//4+1+3+8
    unsigned short numberOfSrc;
    unsigned char   recordType;//data
    unsigned char   auxDataLen;
    unsigned short  numberOfGroupSrc;
    unsigned char    multicastAddress[4];
}igmp_header;

// 定义一些应用层协议使用的端口号

// TCP 协议
#define FTP_PORT 		(21)
#define TELNET_PORT     (23)
#define SMTP_PORT 		(25)
#define HTTP_PORT  		(80)
#define HTTPS_PORT		(443)
#define HTTP2_PORT 		(8080)
#define POP3_PORT 		(110)

// UDP 协议
#define DNS_PORT		(53)
#define SNMP_PORT		(161)

// 网络设备信息结构
struct devInfo{
    std::string strNetDevname;
    std::string strNetDevDescribe;
    std::string strIPV4FamilyName;
    std::string strIPV4Addr;
    std::string strIPV6FamilyName;
    std::string strIPV6Addr;
};

// 捕获的数据结构
struct SnifferData{
    QString				Num;		// 序号
    QString 			Time;		// 时间
    QString             SIP;        // 来源 IP 地址
    QString             DIP;        // 目标 IP 地址
    QString             SPort;      // 来源 IP 端口
    QString             DPort;      // 目标 IP 端口
    QString 			Proto;		// 使用的协议
    QString		        Length;		// 数据长度
    QString             Data;		// 原始数据
};

#endif // NECESSARY_H