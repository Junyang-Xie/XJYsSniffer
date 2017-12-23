#ifndef SNIFFTHREAD_H
#define SNIFFTHREAD_H

#include "necessary.h"
#include "sniffer.h"
#include "tablemodel.h"
#include <QThread>
#include <QMessageBox>
#include <QWidget>
#include <QMap>
#include <QDialogButtonBox>

struct deHeader
{
    char          *prototol;
    unsigned int  len;
    _eth_header   eth;
    _ip_header    iph;
    _arp_header   arph;
    _tcp_header   tcph;
    _udp_header   udph;
    _icmp_header  icmph;
    _igmp_header  igmph;
    _ipv6_header  ipv6h;
};

class sniffThread : public QThread{
    Q_OBJECT
public:
    sniffThread();
    sniffThread(sniffer *psniffer,tableModel *ptableModel);
    ~sniffThread();
    void stop();
    void run();
    void pause();
    bool setRunState(int State);

private:
    int index;
    volatile int runstate;
    sniffer *cap;
    tableModel *tm;
    pcap_pkthdr *Header;
    const u_char *Data;
    //deHeader *decode;
    timeval startTime;
    const u_char *data;
    pcap_pkthdr *header;

    QString timeSub(timeval a);
    QString version(unsigned char ch);
    QString ipHL(unsigned char ch);
    QString uc2bin(unsigned char ch);
    QString uc2hex(unsigned char ch);
    QString ip2qs(unsigned char ch[],bool ipv6mark = 0);
    QString mac2qs(unsigned char ch[]);
    QString us2hex(unsigned short sh);
    //QString filename;
    //MultiView *view;
    //Filter *filter;
    //SlideInfo *pslideInfo;

signals:
    void stateIsChanged(int state);
    void dataWillChear();
    void newItem(int rowNumber);
};

#endif // SNIFFTHREAD_H
