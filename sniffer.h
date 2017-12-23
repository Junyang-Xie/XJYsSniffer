#ifndef SNIFFER_H
#define SNIFFER_H

#include "necessary.h"
#include <QObject>

#define PCAP_OPENFLAG_PROMISCUOUS 0x00000001

class sniffer: public QObject{
    Q_OBJECT
private:
    pcap_if_t *Devices;
    char *nowDev;
    //pcap_dumper_t *File;

private:
    char *snifferErr;
    bool findDevices();
    //int capture();

public:
    pcap_t *Handle;
    QList<devInfo> devsInfo;
    const u_char *Data;
    pcap_pkthdr *Header;

public:
    sniffer();
    ~sniffer();
    bool freeDevices();
    bool closeDevice();
    bool openDevice(char *devName,int flag = PCAP_OPENFLAG_PROMISCUOUS, int timeLimit=100, int lenLimit = 65536);
    bool setConfig(const char *config);
    void getHdrDt(pcap_pkthdr *H,const u_char *D);
    int sniffOnce();
    char *nowDevice();
    QList<QString> getAllDevs();
    bool getDevInfo();
    char *ip2s(sockaddr *sockaddr, int addrlen, bool ipv6flag, char* address = NULL);

/*  About:File
    bool openDumpFile(const char *fileName);
    bool saveData();
    bool closeDumpFile();
*/

};

#endif // SNIFFER_H
