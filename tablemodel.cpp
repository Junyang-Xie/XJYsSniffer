#include "tablemodel.h"

tableModel::tableModel(){
    colNum=0;
    sniffered.clear();
    treeData.clear();
    index = 0;
}

tableModel::tableModel(QList<QString> *sList){
    if(sList->empty()){
        LOG("The number of headers is 0.");
        return;
    }
    colNum = sList->size();

    M.clear();

    int i=0;
    for(QList<QString>::iterator it = sList->begin();it != sList->end();it++,i++){
        M.setHorizontalHeaderItem(i,new QStandardItem(*it));
    }
    if(!sniffered.empty()){
        for(QList<QList<QString>>::iterator it = sniffered.begin();it != sniffered.end();it++)
            it->clear();
    }
    sniffered.clear();
    treeData.clear();
    index = 0;
}

tableModel::~tableModel(){
    if(!sniffered.empty()){
        for(QList<QList<QString>>::iterator it = sniffered.begin();it != sniffered.end();it++)
            it->clear();
    }
    Data.clear();
    rawData.clear();
    sniffered.clear();
    treeData.clear();
}

int tableModel::showIndex(){
    return index;
}

void tableModel::addItemList(QList<QString> *New){
    if(New->size()!=colNum){
        LOG("Row Number ERROR!");
        return;
    }

    int i=0;
    for(QList<QString>::iterator it = New->begin();it != New->end();it++,i++)
        M.setItem(index,i,new QStandardItem(*it));
    sniffered.append(*New);
    index++;
}

void tableModel::clearAll(){
    index=0;

    if(!sniffered.empty()){
        for(QList<QList<QString>>::iterator it = sniffered.begin();it != sniffered.end();it++)
            it->clear();
    }
    Data.clear();
    rawData.clear();
    sniffered.clear();
    treeData.clear();

    clearTable();
}

void tableModel::clearTable(){
    M.removeRows(0,M.rowCount());
}

void tableModel::reBuild(){
    clearTable();

    if(sniffered.empty())
        return;

    for(QList<QList<QString>>::iterator it = sniffered.begin();it != sniffered.end();it++)
        addItemList(&*it);
}

QStandardItemModel* tableModel::Model(){
    return &M;
}

void tableModel::selectRowChanged(const QItemSelection &selected){
    QList<QList<QStandardItem *>>::iterator it=treeData.begin();
    it+=(*(selected.begin()->indexes().begin())).row();
    emit tableModel::treeViewUpgrade(&(*it));
}
