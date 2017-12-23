#ifndef SETVIEW_H
#define SETVIEW_H

#include "necessary.h"
#include <QAbstractItemView>
#include <QTableView>
#include <QHeaderView>
#include <QList>

class defaultView{
private:
    QTableView *v;
public:
    defaultView(QTableView *view,QList<int> *iList=NULL);
    defaultView();
    ~defaultView();
    void setTree();
};

#endif // SETVIEW_H
