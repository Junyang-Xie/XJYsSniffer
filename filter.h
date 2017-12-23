#ifndef FILTER_H
#define FILTER_H

#include "necessary.h"
#include "log.h"
#include <string.h>
#include <QTableView>
#include <regex>
#include <QMap>

#define P 0
#define S 1
#define D 2
#define SPORT 3
#define DPORT 4
#define C 5

class Filter{
public:
    Filter();
    ~Filter();
    bool checkCommand(QString command);
    bool loadCommand(QString command);
    void launchFilter(QTableView* view);
    void printQuery();      //For test
    bool launchOneFilter(SnifferData &snifferData);
    bool fstate();

private:
    bool filState;
    QMap<int, std::string> query;
    std::string findWord(std::string com, size_t pos);

};

#endif // FILTER_H
