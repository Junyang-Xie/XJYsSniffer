
#include "selectinterface.h"
#include "ui_selectinterface.h"
#include "necessary.h"
#include <QWidget>

selectInterface::selectInterface(sniffer *psniffer, QWidget *parent) :
    QDialog(parent = 0),
    ui(new Ui::SelectInterface)
{
    (QObject::tr("SelectInterface"));
    ui->setupUi(this);
    s = psniffer;

    changeLabel();

    QList<QString> tableHeaderName = {"Interface","Address"};
    ifViewModel = new tableModel(&tableHeaderName);
    ui->tableView->setModel(ifViewModel->Model());
    QList<int> tableHeaderWidth = {70,200};
    defaultView *setV = new defaultView(ui->tableView,&tableHeaderWidth);
    ui->tableView->setSelectionMode(QAbstractItemView::NoSelection);

    QList<QString> itemList = s->getAllDevs();
    QList<QString> *tmpItem = new QList<QString>;
    QList<QString>::iterator it=itemList.begin();
    QList<devInfo>::iterator infoIt;
    while(it!=itemList.end()){
        tmpItem->clear();
        tmpItem->append(*it);

        infoIt=s->devsInfo.begin();
        while((infoIt!=s->devsInfo.end())&&((*it)!=infoIt->strNetDevname.data())){
            infoIt++;
        }
        if((*it)==infoIt->strNetDevname.data()){
            std::string tmps="";
            tmps+=infoIt->strIPV4Addr.empty()?"":infoIt->strIPV4Addr;
            if((infoIt->strIPV4Addr.data())!=(infoIt->strIPV6Addr.data()))
                tmps+=infoIt->strIPV6Addr.empty()?"":(infoIt->strIPV4Addr.empty()?"":"/")+infoIt->strIPV4Addr;
            if(tmps.empty())tmpItem->append(QString("NULL"));
            else tmpItem->append(QString(tmps.data()));
        }
        else tmpItem->append(QString("NULL"));

        //if(infoIt->strNetDevDescribe.empty()) tmpItem->append(QString("NULL"));
        //else tmpItem->append(QString(infoIt->strNetDevDescribe.data()));

        ifViewModel->addItemList(tmpItem);
        it++;
    }

    initComboBox();

}

selectInterface::~selectInterface(){
    delete ui;
}

void selectInterface::initComboBox(){
    ui->comboBox->setEditable(false);
    QList<QString> itemList = s->getAllDevs();
    QList<QString>::iterator it;
    for(it=itemList.begin();it!=itemList.end();it++){
        ui->comboBox->insertItem(ui->comboBox->count(),*it);
    }

}

void selectInterface::on_buttonBox_clicked(QAbstractButton *button)
{
    //LOG(button->text()->toStdString());
    if((QPushButton *)button == (ui->buttonBox->button(QDialogButtonBox::Ok)))
    {
        const char *tm1=ui->comboBox->currentText().toStdString().data();
        char *tm2 = new char[strlen(tm1)];
        strcpy(tm2,tm1);

        s->openDevice(tm2);
        emit buttonClicked();
        changeLabel();

        if ( QMessageBox::information(this, tr("XJY's Sniffer"), tr("<p>Change the interface successfully!</p>"), QMessageBox::Ok ) == QMessageBox::Ok) {
            this->hide();
        }
    }
    else if((QPushButton *)button == (ui->buttonBox->button(QDialogButtonBox::Cancel))){
        this->hide();
    }
}

void selectInterface::changeLabel(){
    QString *tmps;
    tmps = new QString("Now Interface is ");
    *tmps += QString(s->nowDevice());
    ui->NowInterface->setText(*tmps);
}
