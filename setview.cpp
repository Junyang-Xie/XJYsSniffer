#include "setView.h"

defaultView::defaultView(){
    LOG("Set View ERROR!");
    return;
}

defaultView::defaultView(QTableView *view,QList<int> *iList){
    v = view;

    if(iList!=NULL){
        int i=0;
        for(QList<int>::iterator it = iList->begin();it != iList->end();it++,i++)
            view->setColumnWidth(i,*it);
    }

    v->horizontalHeader()->resizeSections(QHeaderView::ResizeMode::Fixed);
    v->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    v->verticalHeader()->hide();
    v->horizontalHeader()->show();
    v->setSelectionBehavior(QAbstractItemView::SelectRows);
    v->setSelectionMode(QAbstractItemView::SingleSelection);
    v->setTextElideMode(Qt::ElideRight);
    v->setEditTriggers(QAbstractItemView::NoEditTriggers);
    v->horizontalHeader()->setStretchLastSection(true);
    v->verticalHeader()->setDefaultSectionSize(20);

}

void defaultView::setTree(){
    v->horizontalHeader()->hide();
}
