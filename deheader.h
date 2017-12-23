#ifndef DEHEADER_H
#define DEHEADER_H

#include <QString>
#include "necessary.h"
//IPv6暂缓
/*
class deHeader{
public:
    char          *prototol;
    unsigned int  len;
    _eth_header   *eth;
    _ip_header    *iph;
    _arp_header   *arph;
    _tcp_header   *tcph;
    _udp_header   *udph;
    _icmp_header  *icmph;
    _igmp_header  *igmph;

public:
    deHeader();
    deHeader(const u_char *Data);
    deHeader(const u_char *Data, bpf_u_int32 le);
    ~deHeader();

    QString uc2qs(unsigned char ch);
    QString uc2hex(unsigned char ch);
};
*/
#endif // DEHEADER_H
