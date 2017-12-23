#include "sniffer.h"

sniffer::sniffer(){
    Devices = NULL;
    Handle = NULL;
    //File = NULL;
    findDevices();
    getDevInfo();
    nowDev = Devices->name;
    openDevice(Devices->name);
}

sniffer::~sniffer() {
    closeDevice();
    freeDevices();
    //closeDumpFile();
}

bool sniffer::findDevices() {
    freeDevices();
    if (pcap_findalldevs(&Devices, snifferErr) == -1) {
        return false;
    }
    return true;
}

bool sniffer::openDevice(char *devName, int flag, int timeLimit, int lenLimit) {
    if (Handle != NULL) {
        closeDevice();
    }
    Handle = pcap_open_live(devName, lenLimit, flag, timeLimit, snifferErr);
    if (Handle == NULL) {
        LOG("Handle==null");
        return false;
    }
    nowDev = devName;
    return true;
}

bool sniffer::closeDevice() {
    nowDev = "NULL";
    if (Handle != NULL) {
        pcap_close(Handle);
        Handle = NULL;
        return true;
    }
    return false;
}

bool sniffer::freeDevices() {
    if (Devices != NULL) {
        pcap_freealldevs(Devices);
        Devices = NULL;
        return true;
    }
    return false;
}

bool sniffer::setConfig(const char *config) {
    if (pcap_datalink(Handle) != DLT_EN10MB) {
        LOG("set filter failure");
        return false;
    }
    u_int netmask = 0xffffffff;

    struct bpf_program fcode;

    if (pcap_compile(Handle, &fcode, config, 1, netmask) < 0 ) {
        LOG("pcap_compile failure");
        return false;
    }
    if (pcap_setfilter(Handle, &fcode) < 0) {
        LOG("pcap_setfilter failure");
        return false;
    }
    return true;
}

int sniffer::sniffOnce(){
    if (Handle == NULL) {
        return -2;
    }

    return pcap_next_ex(Handle, &Header, &Data);
}


void sniffer::getHdrDt(pcap_pkthdr *H,const u_char *D){
    H = Header;
    D = Data;
}

char *sniffer::nowDevice(){
    return nowDev;
}

QList<QString> sniffer::getAllDevs(){
    QList<QString> tmp;
    tmp.clear();
    pcap_if_t *dd=Devices;
    while(dd!=NULL){
        tmp.append(QString(dd->name));
        dd = dd->next;
    }
    return tmp;
}

//Get, analysis and save network info
bool sniffer::getDevInfo() {
    if (Devices == NULL) {
        if (findDevices() == false) {
            LOG("no available interfaces");
            return false;
        }
    }
    pcap_addr_t *IPaddr;
    devInfo takenInfo;
    char stripv6[128];
    for (pcap_if_t* i = Devices; i != NULL; i = i->next) {   //for each network interface
        takenInfo.strNetDevname = i->name;
        if (i->description) {
            takenInfo.strNetDevDescribe = i->description;
        }
        else {
            takenInfo.strNetDevDescribe = "No description";
        }
        for (IPaddr = i->addresses; IPaddr != NULL; IPaddr = IPaddr->next) {   //for each address of one interface
            if (IPaddr->addr->sa_family == AF_INET) {
                takenInfo.strIPV4FamilyName="AF_INET/IPv4";
                if(IPaddr->addr) {
                    takenInfo.strIPV4Addr = ip2s(IPaddr->addr, 128, false);
                }
            }
            else if (IPaddr->addr->sa_family == AF_INET6) {
                takenInfo.strIPV6FamilyName="AF_INET/IPv6";
                if(IPaddr->addr) {
                    takenInfo.strIPV6Addr = ip2s(IPaddr->addr, 128, true, stripv6);
                }
            }
        }
        devsInfo.append(takenInfo);
    }
    return true;
}

//transfer socket IP address to sring host name
char* sniffer::ip2s(sockaddr *sockaddr, int addrlen, bool ipv6flag, char* address) {
    if (ipv6flag) {
        socklen_t sockAddrLen = sizeof(struct sockaddr_storage);
        getnameinfo(sockaddr, sockAddrLen, address, addrlen, NULL, 0, NI_NUMERICHOST);
        return address;
    }
    else {
        u_long ip = ((struct sockaddr_in *)sockaddr)->sin_addr.s_addr;
        static char output[12][3*4+3+1];
        static short which;
        u_char *p;
        p = (u_char *)&ip;
        which = (which +1 == 12 ? 0:which+1);
        sprintf(output[which], "%d.%d.%d.%d", p[0],p[1],p[2],p[3]);
        return output[which];
    }
}
