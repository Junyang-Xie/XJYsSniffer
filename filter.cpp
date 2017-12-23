#include "filter.h"

Filter::Filter(){
    filState = false;
}

Filter::~Filter(){

}

/*
 * usage of commands
 * [options=][data] ...
 * pro protocol / src sourceIP / dst destinationIP / sport sourcePort / dport destinationPort
 * using regex to check syntax.
 */

bool Filter::checkCommand(QString command){
    //LOG(command.toLatin1().data());
    QString tmps = command;
    tmps = tmps.remove(' ');
    tmps = tmps.toUpper();
    std::string pattern{ "((PRO=)(UDP|TCP|ICMP|IGMP|IPV6|ARP|IP)|((SRC=)|(DST=))\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3})|(((SPORT=)|(DPORT=))\\d{1,5}))" };
    std::regex re(pattern);
    return std::regex_match(tmps.toStdString(), re);
}

/*
 * load correct command to query structure
 * preparation for function launchFilter.
 */
bool Filter::loadCommand(QString command){
    query.clear();
    if (! checkCommand(command)) {
        filState = false;
        return false;
    }
    filState = true;
    command = command.remove(' ');
    command = command.toUpper();
    std::string com = command.toStdString();
    std::size_t pos;
    pos = com.find("PRO=");
    if (pos<com.size()) query.insert(P, findWord(com, pos+4));
    pos = com.find("SRC=");
    if (pos<com.size()) query.insert(S, findWord(com, pos+4));
    pos = com.find("DST=");
    if (pos<com.size()) query.insert(D, findWord(com, pos+4));
    pos = com.find("SPORT=");
    if (pos<com.size()) query.insert(SPORT, findWord(com, pos+6));
    pos = com.find("DPORT=");
    if (pos<com.size()) query.insert(DPORT, findWord(com, pos+6));
    return true;
}

std::string Filter::findWord(std::string com, size_t pos){
    size_t beg = com.find_first_not_of(std::string(" "), pos);
    size_t end = com.find_first_of(std::string(" "), beg);
    if (end >= com.size()) end = com.find_first_of(std::string("\n"), beg);

    return com.substr(beg, end-beg);
}

bool Filter::launchOneFilter(SnifferData& snifferData){
    bool flag = true;
    for(QMap<int, std::string>::const_iterator iQuery = query.cbegin(); iQuery!=query.cend(); iQuery++) {
        switch(iQuery.key()) {
        case(P):{   //protocal
            if(iQuery.value()!="IP"){
                if (snifferData.Proto.toUpper().toStdString().find(iQuery.value()) > snifferData.Proto.toStdString().length()) {
                    flag = false;
                }
            }
            else{
                flag = false;
                if (snifferData.Proto.toUpper().toStdString().find("UDP") < snifferData.Proto.toStdString().length()) {
                    flag = true;
                }
                if (snifferData.Proto.toUpper().toStdString().find("TCP") < snifferData.Proto.toStdString().length()) {
                    flag = true;
                }
                if (snifferData.Proto.toUpper().toStdString().find("ICMP") < snifferData.Proto.toStdString().length()) {
                    flag = true;
                }
                if (snifferData.Proto.toUpper().toStdString().find("IGMP") < snifferData.Proto.toStdString().length()) {
                    flag = true;
                }
            }
            break;
        }
        case(S):{   //source
            std::string tmpSource = snifferData.SIP.toStdString();
            tmpSource = tmpSource.substr(0,tmpSource.find_first_of(':'));
            if (iQuery.value().find(tmpSource.data()) !=0) {
                flag = false;
            }
            break;
        }
        case(D):{   //destination
            std::string tmpDes = snifferData.DIP.toStdString();
            tmpDes = tmpDes.substr(0,tmpDes.find_first_of(':'));
            if (iQuery.value().find(tmpDes.data()) != 0) {
                flag = false;
            }
            break;
        }
        case(SPORT):{   //source port
            std::string tmpSPort = snifferData.SPort.toStdString();
            if(iQuery.value().find(tmpSPort.data()) != 0) {
                flag = false;
            }
            break;
        }
        case(DPORT):{   //destination port
            std::string tmpDPort = snifferData.DPort.toStdString();
            LOG(tmpDPort.data());
            if(iQuery.value().find(tmpDPort.data()) != 0) {
                flag = false;
            }
            break;
        }
        }
        if (!flag) break;
    }
    return flag;
}

void Filter::launchFilter(QTableView *view){
    /*
    //clear the tableView
    view->rebuildInfo();
    bool flag;
    //filtrate every packet
    for(std::vector<SnifferData>::iterator iSnifferData = view->packets.begin(); iSnifferData<view->packets.end(); iSnifferData++) {
        flag = launchOneFilter(*iSnifferData);

        //add the item to TableView if packet matched
        if (flag) view->addPacketItem(*iSnifferData, false);
    }
    */
}


void Filter::printQuery(){
    LOG("test mode");
    for(QMap<int, std::string>::const_iterator iQuery = query.cbegin(); iQuery!=query.cend(); iQuery++) {
        std::cout<<iQuery.key()<<"  "<<iQuery.value()<<std::endl;
    }
}

bool Filter::fstate(){
    return filState;
}
