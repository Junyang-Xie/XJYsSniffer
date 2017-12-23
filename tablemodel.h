#ifndef TABLEVIEW_H
#define TABLEVIEW_H

#include "necessary.h"
#include <QStandardItemModel>
#include <QList>
#include <QStandardItem>
#include <QItemSelection>

class tableModel:public QObject{
    Q_OBJECT
private:
    int colNum;
    QStandardItemModel M;
    QList<const unsigned char*> rawData;
    int index;

public:
    QList<QList<QString>> sniffered;
    QList<QList<QStandardItem*>> treeData;
    tableModel(QList<QString> *sList);
    QList<SnifferData *> Data;
    tableModel();
    ~tableModel();
    void addItemList(QList<QString> *New);
    void addItemTree(QStandardItem *New);
    void clearAll();
    void clearTable();
    void reBuild();
    int showIndex();
    QStandardItemModel *Model();
    void selectRowChanged(const QItemSelection &selected);

signals:
    void treeViewUpgrade(QList<QStandardItem *> *treeItem);

};

#endif // TABLEVIEW_H
