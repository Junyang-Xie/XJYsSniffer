/*
#include "necessary.h"
#include "deheader.h"

deHeader::deHeader(){
    LOG("still running");
}

deHeader::~deHeader(){

}


deHeader::deHeader(const u_char *Data){

}

deHeader::deHeader(const u_char *Data, bpf_u_int32 le){
    LOG("still running");
    char *data = new char[le+1];
    memcpy(data,Data,le);
    len = 0;
    eth = (_eth_header*) data;
    if(eth->eth_type==EPT_IP){
        LOG("IPV4");
        iph = (_ip_header*) (data+14);
        iph->hl = (unsigned int)iph->ver_ihl%32*4;
        iph->optionLen = iph->hl - 20;
        iph->optionData = (unsigned char*)(data+14+20);
        len += iph->hl;
        switch(iph->proto){
            case ICMP_SIG:{
                icmph = (_icmp_header*)(data+14+iph->hl);
                len += 20;
                prototol = "ICMP";
                break;
            }
            case IGMP_SIG:{
                prototol = "IGMP";
                len += 8;
                break;
            }
            case TCP_SIG:{
                tcph = (_tcp_header*)(data+14+iph->hl);
                tcph->hl = (unsigned int)tcph->thl/32*4;
                tcph->optionLen = iph->hl - 20;
                tcph->optionData = (unsigned char*)(data+14+iph->hl+20);
                prototol = "TCP";
                len += tcph->hl;
                break;
            }
            case UDP_SIG:{
                udph = (_udp_header*)(data+14+iph->hl);
                prototol = "UDP";
                len += 8;
                break;
            }
            default:LOG("No proper IP protocol.");
        }
    }
    else if(eth->eth_type==EPT_ARP){

    }
    else if(eth->eth_type==EPT_IPv6){
        LOG("Part of IPv6 has not been written.");
    }
}

QString deHeader::uc2qs(unsigned char ch){
    char *s = new char[9];
    *(s+8)='\0';
    int ich = int(ch);
    for(int  i=7;i>=0;i--){
        *(s+i)=ich%2+48;
        ich/=2;
    }
    return QString(s);
}

QString deHeader::uc2hex(unsigned char ch){
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
*/
