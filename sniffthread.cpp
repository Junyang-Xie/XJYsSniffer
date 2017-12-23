#include "sniffthread.h"

void sniffThread::stop(){
    LOG("STOP");
    runstate=0;
    flag = true;
}

void sniffThread::run(){
    QList<QStandardItem *> treeItem;
    QMap<unsigned short, int> *map = new QMap<unsigned short, int>;
    deHeader decode;
    SnifferData *snifData;
    runstate = START;
    tm->clearAll();
    index = 1;
    flag = false;
    LOG("start!");
    if(cap->Handle == NULL){
        LOG("Open the interface failed.");
    }

    while(runstate>0){
        if(cap->Handle == NULL){
            runstate = 0;
            emit stateIsChanged(runstate);
        }
        else if(runstate==2){
            if(flag) break;
            msleep(100);
        }
        else{
            snifData = new SnifferData;
            int tmp=cap->sniffOnce();
            header = cap->Header;
            data = cap->Data;

            if(tmp==0) continue;
            else if(tmp==1){
                QStandardItem *childItem;
                QStandardItem *subItem;

                if(index==1) startTime=header->ts;

                //decode the raw data
                decode.len = 14;
                QList<QString> item;
                snifData->Num = QString::number(index);
                item.append(snifData->Num);   //No.
                snifData->Time = timeSub(header->ts);
                item.append(snifData->Time);   //Time

                memcpy(&(decode.eth),data,14);

                //Ethernet Header
                QStandardItem *treeItemEth=new QStandardItem(QObject::tr("Ethernet Header"));
                childItem = new QStandardItem(QObject::tr("Destination: ")+mac2qs(decode.eth.dstmac));
                treeItemEth->appendRow(childItem);
                childItem = new QStandardItem(QObject::tr("Source: ")+mac2qs(decode.eth.srcmac));
                treeItemEth->appendRow(childItem);

                treeItem.append(treeItemEth);


                if(decode.eth.eth_type==EPT_IP){
                    if((decode.eth.eth_type==EPT_IP)){
                    //LOG("IPV4");
                    memcpy(&(decode.iph),data+14,20);
                    decode.iph.hl = (unsigned int)decode.iph.ver_ihl%32*4;
                    decode.iph.optionLen = decode.iph.hl - 20;
                    memcpy(&(decode.iph.optionData),data+14+20,decode.iph.optionLen);
                    decode.len += decode.iph.hl;

                    snifData->SIP = ip2qs(decode.iph.saddr);
                    item.append(snifData->SIP);   //Source

                    snifData->DIP = ip2qs(decode.iph.daddr);
                    item.append(snifData->DIP);   //Destination
                    bool findPro=false;

                    QString tmps;

                    //IP Header
                    QStandardItem *treeItemIP=new QStandardItem(QObject::tr("IP Header"));
                    childItem = new QStandardItem(QObject::tr("Version: ")+QString::number(decode.iph.ver_ihl/16));
                    treeItemIP->appendRow(childItem);

                    childItem = new QStandardItem(QObject::tr("Service: DSCP = ")+QString::number(decode.iph.tos/4)+QObject::tr("  ECN = ")+
                                                  QString::number(decode.iph.tos%4));
                    treeItemIP->appendRow(childItem);

                    childItem = new QStandardItem(QObject::tr("Header Length: ")+QString::number((decode.iph.ver_ihl & 0x0F)*4));
                    treeItemIP->appendRow(childItem);

                    childItem = new QStandardItem(QObject::tr("Total Length: ")+QString::number(ntohs(decode.iph.tlen)));
                    treeItemIP->appendRow(childItem);

                    childItem = new QStandardItem(QObject::tr("Identification: 0x")+QString::number(ntohs(decode.iph.identification),16));
                    treeItemIP->appendRow(childItem);

                    subItem = new QStandardItem(QObject::tr("Flags"));
                    childItem = new QStandardItem(QObject::tr("Reserved Bit: ")+QString::number((ntohs(decode.iph.flags_fo) & 0x8000)/128/256));
                    subItem->appendRow(childItem);
                    childItem = new QStandardItem(QObject::tr("Don't Fragment: ")+QString::number((ntohs(decode.iph.flags_fo) & 0x4000)/64/256));
                    subItem->appendRow(childItem);
                    childItem = new QStandardItem(QObject::tr("More Fragment: ")+QString::number((ntohs(decode.iph.flags_fo) & 0x2000)/32/256));
                    subItem->appendRow(childItem);
                    treeItemIP->appendRow(subItem);

                    childItem = new QStandardItem(QObject::tr("Fragment offset: ")+QString::number(ntohs(decode.iph.flags_fo) & 0x1FFF));
                    treeItemIP->appendRow(childItem);

                    childItem = new QStandardItem(QObject::tr("Time to live: ")+QString::number(decode.iph.ttl));
                    treeItemIP->appendRow(childItem);

                    switch(decode.iph.proto){
                    case ICMP_SIG:{
                        tmps=QString("ICMP");
                        break;
                    }
                    case IGMP_SIG:{
                        tmps=QString("IGMP");
                        break;
                    }
                    case TCP_SIG:{
                        tmps=QString("TCP");
                        break;
                    }
                    case UDP_SIG:{
                        tmps=QString("UDP");
                        break;
                    }
                    default:tmps=QString("Not found");
                    }
                    childItem = new QStandardItem(QObject::tr("Protocal: ")+tmps);
                    treeItemIP->appendRow(childItem);

                    childItem = new QStandardItem(QObject::tr("Header checksum: 0x")+QString::number(ntohs(decode.iph.crc),16));
                    treeItemIP->appendRow(childItem);

                    childItem = new QStandardItem(QObject::tr("Source: ")+ip2qs(decode.iph.saddr));
                    treeItemIP->appendRow(childItem);

                    childItem = new QStandardItem(QObject::tr("Destination: ")+ip2qs(decode.iph.daddr));
                    treeItemIP->appendRow(childItem);

                    tmps=QObject::tr("0x");
                    for(int i=0;i<decode.iph.optionLen;i++)tmps+=uc2hex(decode.iph.optionData[i]);
                    if(decode.iph.optionLen)childItem = new QStandardItem(QObject::tr("Option Data: ")+tmps);
                    else childItem = new QStandardItem(QObject::tr("Option Data: NULL"));
                    treeItemIP->appendRow(childItem);

                    treeItem.append(treeItemIP);

                    switch(decode.iph.proto){
                        case ICMP_SIG:{
                            memcpy(&(decode.icmph),data+14+decode.iph.hl,4);
                            decode.len += 4;
                            decode.prototol = "ICMP";
                            findPro = true;

                            QStandardItem *treeItemICMP = new QStandardItem(QObject::tr("ICMP Header"));

                            childItem = new QStandardItem(QObject::tr("Type: ")+QString::number(decode.icmph.type));
                            treeItemICMP->appendRow(childItem);

                            childItem = new QStandardItem(QObject::tr("Code: ")+QString::number(decode.icmph.code));
                            treeItemICMP->appendRow(childItem);

                            childItem = new QStandardItem(QObject::tr("Checksum: 0x")+QString::number(ntohs(decode.icmph.crc),16));
                            treeItemICMP->appendRow(childItem);

                            treeItem.append(treeItemICMP);

                            break;
                        }
                        case IGMP_SIG:{
                            memcpy(&(decode.igmph),data+14+decode.iph.hl,8);
                            decode.prototol = "IGMP";
                            decode.len += 8;
                            findPro = true;

                            QStandardItem *treeItemIGMP = new QStandardItem(QObject::tr("IGMP Header"));

                            childItem = new QStandardItem(QObject::tr("Type: ")+QString::number(decode.igmph.type));
                            treeItemIGMP->appendRow(childItem);

                            childItem = new QStandardItem(QObject::tr("Max Resp Time: ")+QString::number(decode.igmph.maxRespCode*100)+QObject::tr("ms"));
                            treeItemIGMP->appendRow(childItem);

                            childItem = new QStandardItem(QObject::tr("Checksum: 0x")+QString::number(ntohs(decode.igmph.crc),16));
                            treeItemIGMP->appendRow(childItem);

                            childItem = new QStandardItem(QObject::tr("Multicast Address: ")+ip2qs(decode.igmph.groupAddress));
                            treeItemIGMP->appendRow(childItem);

                            treeItem.append(treeItemIGMP);

                            break;
                        }
                        case TCP_SIG:{
                            memcpy(&(decode.tcph),data+14+decode.iph.hl,20);
                            decode.tcph.hl = (unsigned int)decode.tcph.thl/32*4;
                            decode.tcph.optionLen = decode.iph.hl - 20;
                            memcpy(decode.tcph.optionData,data+14+decode.iph.hl+20,decode.tcph.optionLen);
                            decode.prototol = "TCP";
                            decode.len += decode.tcph.hl;
                            findPro = true;

                            QStandardItem *treeItemTCP = new QStandardItem(QObject::tr("TCP Header"));

                            childItem = new QStandardItem(QObject::tr("Source Port: ")+QString::number(decode.tcph.sport));
                            treeItemTCP->appendRow(childItem);

                            childItem = new QStandardItem(QObject::tr("Destination Port: ")+QString::number(decode.tcph.dport));
                            treeItemTCP->appendRow(childItem);

                            childItem = new QStandardItem(QObject::tr("Sequence number: ")+QString::number(decode.tcph.seq_no));
                            treeItemTCP->appendRow(childItem);

                            childItem = new QStandardItem(QObject::tr("Acknowledgment number: ")+QString::number(decode.tcph.ack_no));
                            treeItemTCP->appendRow(childItem);

                            childItem = new QStandardItem(QObject::tr("Header Length: ")+QString::number(decode.tcph.thl/16*4));
                            treeItemTCP->appendRow(childItem);

                            subItem = new QStandardItem(QObject::tr("Flags"));
                            childItem = new QStandardItem(QObject::tr("Reserved: ")+QString::number((decode.tcph.thl & 0x0E)/2));
                            subItem->appendRow(childItem);
                            childItem = new QStandardItem(QObject::tr("Nonce: ")+QString::number((decode.tcph.thl & 0x01)));
                            subItem->appendRow(childItem);
                            childItem = new QStandardItem(QObject::tr("CWR: ")+QString::number((decode.tcph.flag & 0x80)/128));
                            subItem->appendRow(childItem);
                            childItem = new QStandardItem(QObject::tr("ECN-Echo: ")+QString::number((decode.tcph.flag & 0x40)/64));
                            subItem->appendRow(childItem);
                            childItem = new QStandardItem(QObject::tr("Urgent: ")+QString::number((decode.tcph.flag & 0x20)/32));
                            subItem->appendRow(childItem);
                            childItem = new QStandardItem(QObject::tr("ACK: ")+QString::number((decode.tcph.flag & 0x10)/16));
                            subItem->appendRow(childItem);
                            childItem = new QStandardItem(QObject::tr("Push: ")+QString::number((decode.tcph.flag & 0x8)/8));
                            subItem->appendRow(childItem);
                            childItem = new QStandardItem(QObject::tr("Reset: ")+QString::number((decode.tcph.flag & 0x4)/4));
                            subItem->appendRow(childItem);
                            childItem = new QStandardItem(QObject::tr("Syn: ")+QString::number((decode.tcph.flag & 0x2)/2));
                            subItem->appendRow(childItem);
                            childItem = new QStandardItem(QObject::tr("Fin: ")+QString::number((decode.tcph.flag & 0x1)));
                            subItem->appendRow(childItem);
                            treeItemTCP->appendRow(subItem);

                            childItem = new QStandardItem(QObject::tr("Window size value: ")+QString::number(decode.tcph.wnd_size));
                            treeItemTCP->appendRow(childItem);

                            childItem = new QStandardItem(QObject::tr("Checksum: 0x")+QString::number(decode.tcph.chk_sum,16));
                            treeItemTCP->appendRow(childItem);

                            childItem = new QStandardItem(QObject::tr("Urgent pointer: ")+QString::number(decode.tcph.urgt_p));
                            treeItemTCP->appendRow(childItem);

                            tmps=QObject::tr("0x");
                            for(int i=0;i<decode.tcph.optionLen;i++)tmps+=uc2hex(decode.tcph.optionData[i]);
                            if(decode.tcph.optionLen) childItem = new QStandardItem(QObject::tr("Option Data: ")+tmps);
                            else childItem = new QStandardItem(QObject::tr("Option Data: NULL"));
                            treeItemTCP->appendRow(childItem);

                            treeItem.append(treeItemTCP);

                            snifData->SPort = QString::number(decode.tcph.sport);
                            snifData->DPort = QString::number(decode.tcph.dport);

                            break;
                        }
                        case UDP_SIG:{
                            memcpy(&(decode.udph),data+14+decode.iph.hl,8);
                            decode.prototol = "UDP";
                            decode.len += 8;
                            findPro = true;

                            QStandardItem *treeItemUDP= new QStandardItem(QObject::tr("UDP Header"));

                            childItem = new QStandardItem(QObject::tr("Source Port: ")+QString::number(decode.udph.sport));
                            treeItemUDP->appendRow(childItem);

                            childItem = new QStandardItem(QObject::tr("Destination Port: ")+QString::number(decode.udph.dport));
                            treeItemUDP->appendRow(childItem);

                            childItem = new QStandardItem(QObject::tr("Length: ")+QString::number(decode.udph.len));
                            treeItemUDP->appendRow(childItem);

                            childItem = new QStandardItem(QObject::tr("Checksum: 0x")+QString::number(decode.udph.crc,16));
                            treeItemUDP->appendRow(childItem);

                            treeItem.append(treeItemUDP);

                            snifData->SPort = QString::number(decode.udph.sport);
                            snifData->DPort = QString::number(decode.udph.dport);

                            break;
                        }
                        default:LOG("No proper IP protocol.");
                    }

                    if(findPro) snifData->Proto = QObject::tr(decode.prototol);
                    else snifData->Proto = QString("Not Found");
                    item.append(snifData->Proto);   //Protocal

                    if(((ntohs(decode.iph.flags_fo) & 0x2000)!=0)||(((ntohs(decode.iph.flags_fo) & 0x1FFF)!=0)))
                        if(map->find(decode.iph.identification)!=map->end()){
                            LOG("Find it");
                            int ind=map->find(decode.iph.identification).value();
                            std::cout<<index<<' '<<ind<<std::endl;

                            if((index-ind)<20){
                                QString dataQs("0x");
                                for(int i=decode.len;i<header->len;i++) dataQs+=uc2hex(data[i]);
                                QStandardItem *treeFragData = new QStandardItem(QObject::tr("More fragment: "));
                                childItem = new QStandardItem(QObject::tr("Length: ")+QString::number(ntohs(decode.iph.tlen)));
                                treeFragData->appendRow(childItem);
                                childItem = new QStandardItem(QObject::tr("Data: ")+dataQs);
                                treeFragData->appendRow(childItem);
                                (tm->treeData.begin()+ind-1)->append(treeFragData);

                                treeItem.clear();
                                continue;
                            }
                            else map->insert(decode.iph.identification,index);


                        }
                        else map->insert(decode.iph.identification,index);
                    }
                    else if(decode.eth.eth_type==EPT_ARP){
                        decode.len += 28;
                        memcpy(&(decode.arph),data+14,28);
                        snifData->SIP = ip2qs(decode.arph.arp_spa);
                        item.append(snifData->SIP);
                        snifData->DIP = ip2qs(decode.arph.arp_tpa);
                        item.append(snifData->DIP);
                        snifData->Proto = QObject::tr("ARP");
                        item.append(snifData->Proto);

                        QStandardItem *treeItemARP= new QStandardItem(QObject::tr("ARP Header"));

                        childItem = new QStandardItem(QObject::tr("Hardware type: ")+QString::number(decode.arph.arp_hdw));
                        treeItemARP->appendRow(childItem);

                        childItem = new QStandardItem(QObject::tr("Protocal type: 0x")+QString::number(decode.arph.arp_pr,16));
                        treeItemARP->appendRow(childItem);

                        childItem = new QStandardItem(QObject::tr("Hardware size: ")+QString::number(decode.arph.arp_hl));
                        treeItemARP->appendRow(childItem);

                        childItem = new QStandardItem(QObject::tr("Protocal size: ")+QString::number(decode.arph.arp_pl));
                        treeItemARP->appendRow(childItem);

                        childItem = new QStandardItem(QObject::tr("Opcode: ")+QString::number(decode.arph.arp_pl));
                        treeItemARP->appendRow(childItem);

                        childItem = new QStandardItem(QObject::tr("Sender MAC address: ")+mac2qs(decode.arph.arp_sha));
                        treeItemARP->appendRow(childItem);

                        childItem = new QStandardItem(QObject::tr("Sender IP address: ")+ip2qs(decode.arph.arp_spa));
                        treeItemARP->appendRow(childItem);

                        childItem = new QStandardItem(QObject::tr("Target MAC address: ")+mac2qs(decode.arph.arp_tha));
                        treeItemARP->appendRow(childItem);

                        childItem = new QStandardItem(QObject::tr("Target IP address: ")+ip2qs(decode.arph.arp_tpa));
                        treeItemARP->appendRow(childItem);

                        treeItem.append(treeItemARP);

                        LOG("ARP");
                    }
                    else if(decode.eth.eth_type==EPT_IPv6){
                        decode.len += 40;
                        LOG("IPv6");
                        memcpy(&(decode.ipv6h),data+14,40);
                        snifData->SIP = ip2qs(decode.ipv6h.saddr,true);
                        item.append(snifData->SIP);
                        snifData->DIP = ip2qs(decode.ipv6h.daddr,true);
                        item.append(snifData->DIP);
                        snifData->Proto = QObject::tr("IPv6");
                        item.append(snifData->Proto);
                    }
                    else{
                        snifData->SIP = QObject::tr("No Fit");
                        item.append(snifData->SIP);
                        snifData->DIP = QObject::tr("No Fit");
                        item.append(snifData->DIP);
                        snifData->Proto = QObject::tr("No Fit");
                        item.append(snifData->Proto);
                    }

                    snifData->Length = QString::number(header->len);
                    item.append(snifData->Length);    //Length

                    snifData->Data = QString("0x");
                    for(int i=decode.len;i<header->len;i++) snifData->Data+=uc2hex(data[i]);

                    QStandardItem *treeItemData = new QStandardItem(QObject::tr("Data:")+snifData->Data);
                    treeItem.append(treeItemData);

                    tm->Data.append(snifData);
                    tm->treeData.append(treeItem);
                    treeItem.clear();
                    //item.append(QString("Not Defined."));
                    tm->addItemList(&item);

                    emit newItem(index-1);
                    index++;
                }

            }
        }
    }

    LOG("Thread end");
}

void sniffThread::pause(){
    runstate = 2;
    LOG("runstate = 2");
}


QString sniffThread::timeSub(timeval a){
    if(a.tv_usec<startTime.tv_usec){
        a.tv_usec+=1000000;
        a.tv_sec-=1;
    }
    int us = (a.tv_usec-startTime.tv_usec)/100;
    QString *tmp=new QString((std::to_string(a.tv_sec-startTime.tv_sec)).data());

    *tmp+=QString(".");
    if(us<1000) *tmp+=QString("0");
    if(us<100) *tmp+=QString("0");
    if(us<10) *tmp+=QString("0");
    *tmp+=QString((std::to_string(us)).data());

    return *tmp;
}


QString sniffThread::uc2bin(unsigned char ch){
    char *s = new char[9];
    *(s+8)='\0';
    int ich = int(ch);
    for(int  i=7;i>=0;i--){
        *(s+i)=ich%2+48;
        ich/=2;
    }
    return QString(s);
}

QString sniffThread::uc2hex(unsigned char ch){
    char *s = new char[3];
    *(s+2)='\0';
    int ich = int(ch);
    for(int  i=1;i>=0;i--){
        if(ich%16<=9) *(s+i)='0'+ich%16;
        else *(s+i)='A'+ich%16-10;
        ich/=16;
    }
    return QString(s);
}

QString sniffThread::ipHL(unsigned char ch){
    char *s = new char[10];
    s[0]=s[1]=s[2]=s[3]='.';s[8]='=';s[9]='\0';
    int ich=ch;
    int i=16;
    for(int j=4;j<8;j++,i/=2) *(s+j)=(ich&i)?'1':'0';
    ich=ich%16;
    QString tmps(s);
    tmps+=QString("Header Length:");
    tmps+=QString((std::to_string(i*4)).data());
    tmps+=QString(" bytes");
    return tmps;
}

QString sniffThread::us2hex(unsigned short sh){
    char *s = new char[7];
    s[0]='0';s[1]='x';s[6]='\0';
    int ish=sh;
    for(int j=5;j>1;j--,ish/=16) *(s+j)=(ish%16<10)?48+ish%16:55+ish%16;
    return QString(s);
}

QString sniffThread::ip2qs(unsigned char ch[],bool ipv6mark){
    QString tmps("");
    if(!ipv6mark) for(int i=0;i<4;i++){
        tmps+=QString::number(ch[i]);
        if(i!=3) tmps+=QString(".");
    }
    else for(int i=0;i<16;i++){
        tmps+=uc2hex(ch[i]);
        if(i%2)tmps+=QObject::tr(":");
    }
    return tmps;
}

QString sniffThread::mac2qs(unsigned char ch[]){
    QString tmps("");
    for(int i=0;i<6;i++){
        tmps+=uc2hex(ch[i]);
        if(i!=5) tmps+=QString(":");
    }
    return tmps;
}

sniffThread::sniffThread(){

}

sniffThread::sniffThread(sniffer *psniffer,tableModel *ptableModel){
    cap = psniffer;
    tm = ptableModel;
    runstate = 0;
    //decode = NULL;
}

bool sniffThread::setRunState(int state){
    if(state!=runstate){
        runstate = state;
        return true;
    }
    return false;
}

sniffThread::~sniffThread(){

}
